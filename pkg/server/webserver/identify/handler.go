package identify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/seal-io/utils/funcx"
	"github.com/seal-io/utils/httpx"
	"github.com/seal-io/utils/stringx"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/clients/clientset"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubeconfig"
	"github.com/seal-io/walrus/pkg/system"
	"github.com/seal-io/walrus/pkg/systemkuberes"
	"github.com/seal-io/walrus/pkg/systemsetting"
)

func Route(r *mux.Route) {
	sr := r.Subrouter()

	sr.Path("/providers").Methods(http.MethodGet).
		HandlerFunc(providers)
	sr.Path("/login").Methods(http.MethodGet, http.MethodPost).
		HandlerFunc(login)
	sr.Path("/callback/{provider}").Methods(http.MethodGet).
		HandlerFunc(callback)
	sr.Path("/profile").Methods(http.MethodGet, http.MethodPut).
		HandlerFunc(profile)
	sr.Path("/token").Methods(http.MethodGet).
		HandlerFunc(token)
	sr.Path("/logout").Methods(http.MethodGet).
		HandlerFunc(logout)
}

type (
	responseProvider struct {
		Name              string `json:"name"`
		Type              string `json:"type"`
		DisplayName       string `json:"displayName"`
		Description       string `json:"description"`
		LoginWithPassword bool   `json:"loginWithPassword"`
	}
	responseProviderList struct {
		Items []responseProvider `json:"items"`
	}
)

// providers is a handler to list all providers.
//
// GET: /providers
func providers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// List.
	subjProvList := new(walrus.SubjectProviderList)
	{
		cli := system.LoopbackCtrlClient.Get()
		err := cli.List(ctx, subjProvList, ctrlcli.InNamespace(systemkuberes.SystemNamespaceName))
		if err != nil {
			responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("list providers: %w", err))
			return
		}
	}

	// Output.
	resp := responseProviderList{
		Items: make([]responseProvider, 0, len(subjProvList.Items)),
	}
	for i := range subjProvList.Items {
		resp.Items = append(resp.Items, responseProvider{
			Name:              subjProvList.Items[i].Name,
			Type:              subjProvList.Items[i].Spec.Type.String(),
			DisplayName:       subjProvList.Items[i].Spec.DisplayName,
			Description:       subjProvList.Items[i].Spec.Description,
			LoginWithPassword: subjProvList.Items[i].Status.LoginWithPassword,
		})
	}
	httpx.JSON(w, http.StatusOK, resp)
}

type (
	requestLogin struct {
		Provider string `query:"provider"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

// login is a handler to log in.
//
// POST/GET: /login?provider={provider}
func login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request.
	var req requestLogin
	_ = httpx.BindWith(r, &req, httpx.BindJSON, httpx.BindQuery)

	// Login with username and password.
	if req.Provider == "" || req.Provider == systemkuberes.DefaultSubjectProviderName {
		if r.Method != http.MethodPost {
			responseErrorWithCode(w, http.StatusMethodNotAllowed, nil)
			return
		}

		if req.Username == "" {
			responseErrorWithCode(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		if req.Password == "" {
			responseErrorWithCode(w, http.StatusBadRequest, errors.New("password is required"))
			return
		}

		subj := &walrus.Subject{
			ObjectMeta: meta.ObjectMeta{
				Namespace: systemkuberes.SystemNamespaceName,
				Name:      req.Username,
			},
			Spec: walrus.SubjectSpec{
				Credential: ptr.To(req.Password),
			},
		}

		loginSubject(w, r, subj)
		return
	}

	// Get provider.
	subjProv, err := getSubjectProvider(ctx, req.Provider)
	if err != nil {
		responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get provider: %w", err))
		return
	}

	// Get connector.
	conn, err := getExternalConnectorFromSubjectProvider(subjProv)
	if err != nil {
		renderErrorWithCode(w, http.StatusInternalServerError, err)
		return
	}

	switch cn := conn.(type) {
	default:
		responseErrorWithCode(w, http.StatusBadRequest, errors.New("unsupported provider type"))
		return
	case ExternalPasswordConnector:
		// Login with password, like LDAP.

		if r.Method != http.MethodPost {
			responseErrorWithCode(w, http.StatusMethodNotAllowed, nil)
			return
		}

		if req.Username == "" {
			responseErrorWithCode(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		if req.Password == "" {
			responseErrorWithCode(w, http.StatusBadRequest, errors.New("password is required"))
			return
		}

		id, valid, err := cn.Login(ctx, req.Username, req.Password)
		if err != nil {
			responseErrorWithCode(w, http.StatusInternalServerError, err)
			return
		}
		if !valid {
			responseErrorWithCode(w, http.StatusUnauthorized, errors.New("login failed"))
			return
		}

		subj, err := getSubject(ctx, req.Provider, id)
		if err != nil {
			responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get subject: %w", err))
			return
		}

		loginSubject(w, r, subj)
	case ExternalCallbackConnector:
		// Redirect to OAuth login page.

		if r.Method != http.MethodGet {
			responseErrorWithCode(w, http.StatusMethodNotAllowed, nil)
			return
		}

		// Create state.
		sec := &core.Secret{
			ObjectMeta: meta.ObjectMeta{
				Namespace:    systemkuberes.SystemNamespaceName,
				GenerateName: "walrus-subject-login-callback-",
			},
			Data: map[string][]byte{
				"provider": []byte(req.Provider),
				"clientID": []byte(cn.GetClientID()),
			},
		}
		sec, err := kubeclientset.CreateWithCtrlClient(ctx, system.LoopbackCtrlClient.Get(), sec)
		if err != nil {
			responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("create state: %w", err))
			return
		}

		// Get callback URL.
		var callbackUrl string
		{
			u := r.URL.ResolveReference(&url.URL{Path: "callback/" + req.Provider})
			u.RawQuery = ""
			u.RawFragment = ""
			u.Fragment = ""
			su := funcx.NoError(systemsetting.ServeUrl.ValueURL(ctx))
			if su == nil || su.Scheme == "" && su.Host == "" {
				u.Scheme = "https"
				u.Host = "localhost"
			} else {
				u.Scheme = su.Scheme
				u.Host = su.Host
			}
			callbackUrl = u.String()
		}

		loginUrl, err := cn.GetLoginURL(callbackUrl, sec.Name)
		if err != nil {
			responseErrorWithCode(w, http.StatusInternalServerError, err)
			return
		}

		http.Redirect(w, r, loginUrl, http.StatusFound)
	}
}

type (
	requestCallback struct {
		Provider string `path:"provider"`
		State    string `query:"state"`
	}
)

// callback is a handler to handle callback.
//
// GET: /callback/{provider}?code={code}&state={state}
func callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request.
	var req requestCallback
	_ = httpx.BindWith(r, &req, httpx.BindQuery, httpx.BindPath)

	// Get provider.
	subjProv, err := getSubjectProvider(ctx, req.Provider)
	if err != nil {
		renderErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get provider: %w", err))
		return
	}

	// Get connector.
	var cn ExternalCallbackConnector
	{
		conn, err := getExternalConnectorFromSubjectProvider(subjProv)
		if err != nil {
			renderErrorWithCode(w, http.StatusInternalServerError, err)
			return
		}
		var ok bool
		cn, ok = conn.(ExternalCallbackConnector)
		if !ok {
			http.Error(w, "unsupported provider type", http.StatusBadRequest)
			return
		}
	}

	// Handle callback.
	id, err := cn.HandleCallback(r)
	if err != nil {
		renderErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("handle callback: %w", err))
		return
	}

	// Verify state.
	{
		sec := &core.Secret{
			ObjectMeta: meta.ObjectMeta{
				Namespace: subjProv.Namespace,
				Name:      req.State,
			},
		}
		cli := system.LoopbackCtrlClient.Get()
		err = cli.Get(ctx, ctrlcli.ObjectKeyFromObject(sec), sec)
		if err != nil {
			if !kerrors.IsNotFound(err) {
				renderErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get state: %w", err))
			} else {
				renderErrorWithCode(w, http.StatusForbidden, errors.New("state not found"))
			}
			return
		}
		_ = cli.Delete(ctx, sec) // Always delete.

		err = func() error {
			switch {
			case string(sec.Data["provider"]) != req.Provider:
				return errors.New("provider mismatch")
			case string(sec.Data["clientID"]) != cn.GetClientID():
				return errors.New("client id mismatch")
			case time.Since(sec.CreationTimestamp.Time) > 5*time.Minute:
				return errors.New("state expired")
			}
			return nil
		}()
		if err != nil {
			renderErrorWithCode(w, http.StatusForbidden, err)
			return
		}
	}

	// Get subject.
	subj, err := getSubject(ctx, req.Provider, id)
	if err != nil {
		renderErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get subject: %w", err))
		return
	}

	// Login.
	loginSubject(w, r, subj)
}

type (
	requestProfile struct {
		DisplayName *string `json:"displayName,omitempty"`
		Email       *string `json:"email,omitempty"`
		Password    *string `json:"password,omitempty"`
	}
	responseProfile struct {
		Subject walrus.SubjectSpec                     `json:"subject"`
		Review  authorization.SubjectRulesReviewStatus `json:"review"`
	}
)

// profile is a handler to get/update profile.
//
// GET/PUT: /profile
func profile(w http.ResponseWriter, r *http.Request) {
	// Get session.
	rt, t := fetchSession(r)
	if t == nil {
		responseErrorWithCode(w, http.StatusUnauthorized, errors.New("unauthorized: no token"))
		return
	}

	// Parse subject.
	subjNamespace, subjName, ok := strings.Cut(t.Subject(), ":")
	if !ok {
		responseErrorWithCode(w, http.StatusUnauthorized, errors.New("unauthorized: invalid token"))
		return
	}

	// Get kube client.
	cli, err := getSubjectKubeClient(rt)
	if err != nil {
		responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get kube client: %w", err))
		return
	}

	if r.Method == http.MethodGet {
		// Get profile.
		subj, err := cli.WalrusV1().Subjects(subjNamespace).
			Get(r.Context(), subjName, meta.GetOptions{ResourceVersion: "0"})
		if err != nil {
			responseError(w, fmt.Errorf("get profile: %w", err))
			return
		}

		// Get rules.
		subjRules, err := cli.AuthorizationV1().SelfSubjectRulesReviews().
			Create(r.Context(), new(authorization.SelfSubjectRulesReview), meta.CreateOptions{})
		if err != nil {
			responseError(w, fmt.Errorf("get access list: %w", err))
			return
		}

		resp := responseProfile{
			Subject: subj.Spec,
			Review:  subjRules.Status,
		}

		httpx.JSON(w, http.StatusOK, resp)
	}

	// Parse request.
	var req requestProfile
	_ = httpx.BindJSON(r, &req)

	// Update profile.
	eSubj := &walrus.Subject{
		ObjectMeta: meta.ObjectMeta{
			Namespace: subjNamespace,
			Name:      subjName,
		},
	}
	if req.DisplayName != nil {
		eSubj.Spec.DisplayName = *req.DisplayName
	}
	if req.Email != nil {
		eSubj.Spec.Email = *req.Email
	}
	if req.Password != nil {
		eSubj.Spec.Credential = req.Password
	}
	_, err = kubeclientset.Apply(r.Context(), cli.WalrusV1().Subjects(subjNamespace), eSubj)
	if err != nil {
		responseError(w, fmt.Errorf("update profile: %w", err))
	}
}

type (
	requestToken struct {
		ExpirationSeconds *int64 `query:"expirationSeconds"`
	}
)

// token is a handler to get token.
//
// GET: /token?expirationSeconds={expirationSeconds}
func token(w http.ResponseWriter, r *http.Request) {
	// Get session.
	rt, t := fetchSession(r)
	if t == nil {
		responseErrorWithCode(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	// Parse subject.
	subjNamespace, subjName, ok := strings.Cut(t.Subject(), ":")
	if !ok {
		responseErrorWithCode(w, http.StatusUnauthorized, errors.New("unauthorized: invalid token"))
		return
	}

	// Get kube client.
	cli, err := getSubjectKubeClient(rt)
	if err != nil {
		responseErrorWithCode(w, http.StatusInternalServerError, fmt.Errorf("get kube client: %w", err))
		return
	}

	// Parse request.
	var req requestToken
	_ = httpx.BindQuery(r, &req)

	// Create.
	subjToken := &walrus.SubjectToken{
		Spec: walrus.SubjectTokenSpec{
			ExpirationSeconds: req.ExpirationSeconds,
		},
	}
	subjToken, err = cli.WalrusV1().Subjects(subjNamespace).
		CreateToken(r.Context(), subjName, subjToken, meta.CreateOptions{})
	if err != nil {
		responseError(w, fmt.Errorf("create token: %w", err))
		return
	}

	httpx.JSON(w, http.StatusOK, subjToken.Status)
}

// logout is a handler to log out.
//
// GET: /logout
func logout(w http.ResponseWriter, r *http.Request) {
	revertSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

const (
	_AuthenticationCookie = "walrus_session"

	_AuthorizationHeader       = "Authorization"
	_AuthorizationBearerPrefix = "Bearer "
	_AuthorizationBasicPrefix  = "Basic "
)

func fetchSession(r *http.Request) (rt string, t jwt.Token) {
	if r == nil {
		return
	}

	if c, err := r.Cookie(_AuthenticationCookie); err == nil {
		rt = c.Value
		t, _ = jwt.Parse(stringx.ToBytes(&rt))
		return
	}

	h := r.Header.Get(_AuthorizationHeader)
	if h == "" {
		return
	}

	if strings.HasPrefix(h, _AuthorizationBearerPrefix) {
		rt = strings.TrimPrefix(h, _AuthorizationBearerPrefix)
		t, _ = jwt.Parse(stringx.ToBytes(&rt))
		return
	}

	if strings.HasPrefix(h, _AuthorizationBasicPrefix) {
		c, err := stringx.DecodeBase64(strings.TrimPrefix(h, _AuthorizationBasicPrefix))
		if err != nil {
			return
		}
		_, p, ok := strings.Cut(c, ":")
		if !ok {
			return
		}
		rt = p
		t, _ = jwt.Parse(stringx.ToBytes(&rt))
		return
	}

	return
}

func assignSession(w http.ResponseWriter, token string) {
	exp := funcx.NoError(jwt.Parse(stringx.ToBytes(&token))).Expiration()
	c := &http.Cookie{
		Name:     _AuthenticationCookie,
		Value:    token,
		Path:     "/",
		Domain:   "",
		Secure:   true,
		HttpOnly: true,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Round(time.Second) / time.Second),
	}
	http.SetCookie(w, c)
}

func revertSession(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     _AuthenticationCookie,
		Value:    "",
		Path:     "/",
		Domain:   "",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
	}
	http.SetCookie(w, c)
}

func getSubjectProvider(ctx context.Context, provider string) (*walrus.SubjectProvider, error) {
	subjProv := &walrus.SubjectProvider{
		ObjectMeta: meta.ObjectMeta{
			Namespace: systemkuberes.SystemNamespaceName,
			Name:      provider,
		},
	}
	cli := system.LoopbackCtrlClient.Get()
	err := cli.Get(ctx, ctrlcli.ObjectKeyFromObject(subjProv), subjProv)
	if err != nil {
		return nil, err
	}
	return subjProv, nil
}

func getSubject(ctx context.Context, provider string, id *ExternalIdentity) (*walrus.Subject, error) {
	sort.Strings(id.Groups)

	// Normalize.
	name := id.PreferredUsername
	displayName := id.Username
	if stringx.StringWidth(name) > stringx.StringWidth(displayName) {
		name, displayName = displayName, name
	}
	name = strings.TrimSpace(strings.ToLower(name))
	name = stringx.ReplaceFunc(name, func(r rune) rune {
		if r == '.' || r == '-' || unicode.IsOneOf(
			[]*unicode.RangeTable{unicode.Number, unicode.Letter}, r) {
			return r
		}
		return '-'
	})

	// Create or update.
	eSubj := &walrus.Subject{
		ObjectMeta: meta.ObjectMeta{
			Namespace: systemkuberes.SystemNamespaceName,
			Name:      stringx.Join(".", provider, name), // NB(thxCode): make sure the name is unique.
		},
		Spec: walrus.SubjectSpec{
			Provider:    provider,
			Role:        walrus.SubjectRoleViewer,
			DisplayName: displayName,
			Description: "Login from provider",
			Email:       id.Email,
			Groups:      id.Groups,
			Credential:  ptr.To(stringx.SumBytesBySHA256(id.ConnectorData)),
		},
	}
	alignFn := func(aSubj *walrus.Subject) (*walrus.Subject, bool, error) {
		aSubj.Spec.Groups = eSubj.Spec.Groups
		aSubj.Spec.Credential = eSubj.Spec.Credential
		return aSubj, false, nil
	}
	subj, err := kubeclientset.UpdateWithCtrlClient(ctx, system.LoopbackCtrlClient.Get(), eSubj,
		kubeclientset.WithUpdateAlign(alignFn),
		kubeclientset.WithCreateIfNotExisted[*walrus.Subject]())
	if err != nil {
		return nil, err
	}

	// Since the credential is a write-only field, it is not returned.
	// We need to copy the credential back.
	subj.Spec.Credential = eSubj.Spec.Credential
	return subj, nil
}

func getSubjectKubeClient(token string) (clientset.Interface, error) {
	cliCfg, err := kubeconfig.WrapRestConfigWithAuthInfo(system.LoopbackKubeClientConfig.Get(),
		clientcmdapi.AuthInfo{Token: token})
	if err != nil {
		return nil, err
	}

	return clientset.NewForConfig(cliCfg)
}

func loginSubject(w http.ResponseWriter, r *http.Request, subj *walrus.Subject) {
	cli := system.LoopbackKubeClient.Get()

	subjl := &walrus.SubjectLogin{
		ObjectMeta: meta.ObjectMeta{
			Namespace: systemkuberes.SystemNamespaceName,
			Name:      subj.Name,
		},
		Spec: walrus.SubjectLoginSpec{
			Credential: *subj.Spec.Credential,
		},
	}

	subjl, err := cli.WalrusV1().Subjects(systemkuberes.SystemNamespaceName).
		Login(r.Context(), subj.Name, subjl, meta.CreateOptions{})
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case kerrors.IsInvalid(err):
			code = http.StatusBadRequest
		case kerrors.IsBadRequest(err):
			code = http.StatusBadRequest
		}
		renderErrorWithCode(w, code, fmt.Errorf("login: %w", err))
		return
	}

	assignSession(w, subjl.Status.Token)
	http.Redirect(w, r, "/", http.StatusFound)
}

func responseErrorWithCode(w http.ResponseWriter, code int, err error) {
	s := meta.Status{
		Status: meta.StatusFailure,
		Reason: meta.StatusReason(stringx.TrimAllSpace(http.StatusText(code))),
		Code:   int32(code),
	}
	if err != nil {
		s.Message = err.Error()
	}

	httpx.JSON(w, code, s)
}

func responseError(w http.ResponseWriter, err error) {
	rerr := errors.Unwrap(err)
	switch {
	case kerrors.IsInvalid(rerr):
		responseErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsUnauthorized(rerr):
		responseErrorWithCode(w, http.StatusUnauthorized, err)
	case kerrors.IsNotFound(rerr):
		responseErrorWithCode(w, http.StatusNotFound, err)
	default:
		responseErrorWithCode(w, http.StatusInternalServerError, err)
	}
}

func renderErrorWithCode(w http.ResponseWriter, code int, err error) {
	s := meta.Status{
		Status: meta.StatusFailure,
		Reason: meta.StatusReason(stringx.TrimAllSpace(http.StatusText(code))),
		Code:   int32(code),
	}
	if err != nil {
		s.Message = err.Error()
	}

	// TODO: redirect to error page
	httpx.JSON(w, code, s)
}
