package identify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	dexconnector "github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/bitbucketcloud"
	"github.com/dexidp/dex/connector/gitea"
	"github.com/dexidp/dex/connector/github"
	"github.com/dexidp/dex/connector/gitlab"
	"github.com/dexidp/dex/connector/google"
	"github.com/dexidp/dex/connector/ldap"
	"github.com/dexidp/dex/connector/microsoft"
	"github.com/dexidp/dex/connector/oauth"
	"github.com/dexidp/dex/connector/oidc"
	dexserver "github.com/dexidp/dex/server"
	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
)

type (
	ExternalIdentity          = dexconnector.Identity
	ExternalConnectorConfig   = dexserver.ConnectorConfig
	ExternalConnector         = dexconnector.Connector
	ExternalPasswordConnector interface {
		Login(ctx context.Context, username, password string) (id *ExternalIdentity, valid bool, err error)
	}
	ExternalCallbackConnector interface {
		GetLoginURL(callbackUrl, state string) (loginUrl string, err error)
		GetClientID() string
		HandleCallback(req *http.Request) (id *ExternalIdentity, err error)
	}
)

type _ExternalPasswordProvider struct {
	ConnConfig ExternalConnectorConfig
}

func NewExternalPasswordProvider(connConfig ExternalConnectorConfig) ExternalPasswordConnector {
	return &_ExternalPasswordProvider{ConnConfig: connConfig}
}

func (p *_ExternalPasswordProvider) openConnector() (dexconnector.PasswordConnector, error) {
	lg := logrus.New()
	lg.SetOutput(klog.Background().WithName("identify"))
	conn, err := p.ConnConfig.Open("", lg)
	if err != nil {
		return nil, err
	}
	return conn.(dexconnector.PasswordConnector), nil
}

func (p *_ExternalPasswordProvider) Login(ctx context.Context, username, password string) (*ExternalIdentity, bool, error) {
	conn, err := p.openConnector()
	if err != nil {
		return nil, false, fmt.Errorf("open connector: %w", err)
	}
	id, ok, err := conn.Login(ctx, dexconnector.Scopes{Groups: true, OfflineAccess: true}, username, password)
	if err != nil {
		return nil, false, fmt.Errorf("login failed : %w", err)
	}
	return &id, ok, nil
}

type _ExternalCallbackProvider[T ExternalConnectorConfig] struct {
	ConnConfig        T
	ClientID          string
	InjectCallbackUrl func(callbackUrl string, ConnConfig T)
}

func NewExternalCallbackProvider[T ExternalConnectorConfig](connConfig T, clientID string, injectCallbackUrl func(string, T)) ExternalCallbackConnector { // nolint:lll
	return &_ExternalCallbackProvider[T]{
		ConnConfig:        connConfig,
		ClientID:          clientID,
		InjectCallbackUrl: injectCallbackUrl,
	}
}

func (p *_ExternalCallbackProvider[T]) openConnector() (dexconnector.CallbackConnector, error) {
	lg := logrus.New()
	lg.SetOutput(klog.Background().WithName("identify"))
	conn, err := p.ConnConfig.Open("", lg)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}
	return conn.(dexconnector.CallbackConnector), nil
}

func (p *_ExternalCallbackProvider[T]) GetLoginURL(callbackUrl, state string) (string, error) {
	if p.InjectCallbackUrl != nil {
		p.InjectCallbackUrl(callbackUrl, p.ConnConfig)
	}

	conn, err := p.openConnector()
	if err != nil {
		return "", fmt.Errorf("open connector: %w", err)
	}
	u, err := conn.LoginURL(dexconnector.Scopes{Groups: true, OfflineAccess: true}, callbackUrl, state)
	if err != nil {
		return "", fmt.Errorf("get login url failed: %w", err)
	}
	return u, nil
}

func (p *_ExternalCallbackProvider[T]) GetClientID() string {
	return p.ClientID
}

func (p *_ExternalCallbackProvider[T]) HandleCallback(req *http.Request) (*ExternalIdentity, error) {
	conn, err := p.openConnector()
	if err != nil {
		return nil, fmt.Errorf("open connector: %w", err)
	}
	id, err := conn.HandleCallback(dexconnector.Scopes{Groups: true, OfflineAccess: true}, req)
	if err != nil {
		return nil, fmt.Errorf("handle callback failed: %w", err)
	}
	return &id, nil
}

// getExternalConnectorFromSubjectProvider converts a Walrus SubjectProvider to ExternalConnector.
func getExternalConnectorFromSubjectProvider(subjProv *walrus.SubjectProvider) (ExternalConnector, error) {
	if subjProv == nil {
		return nil, errors.New("provider is nil")
	}

	if subjProv.Spec.Type == walrus.SubjectProviderTypeInternal {
		return nil, errors.New("internal provider is not supported")
	}

	err := subjProv.Spec.ExternalConfig.ValidateWithType(subjProv.Spec.Type)
	if err != nil {
		return nil, fmt.Errorf("provider: invalid external config: %w", err)
	}

	switch subjProv.Spec.Type {
	default:
		return nil, fmt.Errorf("provider: unsupported type: %s", subjProv.Spec.Type)
	case walrus.SubjectProviderTypeLDAP:
		src := subjProv.Spec.ExternalConfig.Ldap
		dst := &ldap.Config{
			InsecureSkipVerify: src.SkipInsecureVerify,
			Host:               src.Host,
			BindDN:             src.ServiceAccountDN,
			BindPW:             src.ServiceAccountPassword,
		}
		if _, port, _ := net.SplitHostPort(src.Host); port == "389" {
			dst.InsecureNoSSL = true
		}
		dst.UserSearch.BaseDN = src.UserSearch.BaseDN
		dst.UserSearch.Filter = src.UserSearch.Filter
		dst.UserSearch.Username = src.UserSearch.NameAttribute
		dst.UserSearch.Scope = "sub"
		dst.UserSearch.IDAttr = "uid"
		dst.UserSearch.EmailAttr = src.UserSearch.EmailAttribute
		dst.UserSearch.NameAttr = src.UserSearch.NameAttribute
		dst.UserSearch.PreferredUsernameAttrAttr = src.UserSearch.DisplayNameAttribute
		dst.GroupSearch.BaseDN = src.GroupSearch.BaseDN
		dst.GroupSearch.Filter = src.GroupSearch.Filter
		dst.GroupSearch.Scope = "sub"
		for _, um := range src.GroupSearch.UserMatchers {
			dst.GroupSearch.UserMatchers = append(dst.GroupSearch.UserMatchers,
				ldap.UserMatcher{
					UserAttr:  um.UserAttribute,
					GroupAttr: um.GroupAttribute,
				})
		}
		dst.GroupSearch.NameAttr = src.GroupSearch.NameAttribute
		return NewExternalPasswordProvider(dst), nil
	case walrus.SubjectProviderTypeOAuth:
		src := subjProv.Spec.ExternalConfig.OAuth
		dst := &oauth.Config{
			InsecureSkipVerify: src.SkipInsecureVerify,
			ClientID:           src.ClientID,
			ClientSecret:       src.ClientSecret,
			TokenURL:           src.TokenEndpoint,
			AuthorizationURL:   src.AuthorizationEndpoint,
			UserInfoURL:        src.UserinfoEndpoint,
		}
		if cm := src.ClaimMapping; cm != nil {
			dst.ClaimMapping.UserNameKey = cm.NameKey
			dst.ClaimMapping.PreferredUsernameKey = cm.DisplayNameKey
			dst.ClaimMapping.EmailKey = cm.EmailKey
			dst.ClaimMapping.GroupsKey = cm.GroupsKey
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *oauth.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeOIDC:
		src := subjProv.Spec.ExternalConfig.Oidc
		dst := &oidc.Config{
			InsecureSkipVerify:   src.SkipInsecureVerify,
			Issuer:               src.Issuer,
			ClientID:             src.ClientID,
			ClientSecret:         src.ClientSecret,
			InsecureEnableGroups: true,
			PromptType:           ptr.To("consent"),
		}
		if cm := src.ClaimMapping; cm != nil {
			dst.UserNameKey = cm.NameKey
			dst.ClaimMapping.PreferredUsernameKey = cm.DisplayNameKey
			dst.ClaimMapping.EmailKey = cm.EmailKey
			dst.ClaimMapping.GroupsKey = cm.GroupsKey
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *oidc.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeGithub:
		src := subjProv.Spec.ExternalConfig.Github
		dst := &github.Config{
			ClientID:      src.ClientID,
			ClientSecret:  src.ClientSecret,
			TeamNameField: "both",
			UseLoginAsID:  true,
		}
		for k, v := range src.Groups.ToMap() {
			dst.Orgs = append(dst.Orgs, github.Org{
				Name:  k,
				Teams: v,
			})
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *github.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeGitlab:
		src := subjProv.Spec.ExternalConfig.Gitlab
		dst := &gitlab.Config{
			ClientID:     src.ClientID,
			ClientSecret: src.ClientSecret,
			Groups:       src.Groups,
			UseLoginAsID: true,
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *gitlab.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeBitbucket:
		src := subjProv.Spec.ExternalConfig.Bitbucket
		dst := &bitbucketcloud.Config{
			ClientID:          src.ClientID,
			ClientSecret:      src.ClientSecret,
			Teams:             src.Groups,
			IncludeTeamGroups: true,
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *bitbucketcloud.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeGitea:
		src := subjProv.Spec.ExternalConfig.Gitea
		dst := &gitea.Config{
			ClientID:      src.ClientID,
			ClientSecret:  src.ClientSecret,
			LoadAllGroups: len(src.Groups) == 0,
			UseLoginAsID:  true,
		}
		for k, v := range src.Groups.ToMap() {
			dst.Orgs = append(dst.Orgs, gitea.Org{
				Name:  k,
				Teams: v,
			})
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *gitea.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeGoogle:
		src := subjProv.Spec.ExternalConfig.Google
		dst := &google.Config{
			ClientID:     src.ClientID,
			ClientSecret: src.ClientSecret,
			Groups:       src.Groups,
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *google.Config) { o.RedirectURI = s }), nil
	case walrus.SubjectProviderTypeMicrosoft:
		src := subjProv.Spec.ExternalConfig.Microsoft
		dst := &microsoft.Config{
			ClientID:         src.ClientID,
			ClientSecret:     src.ClientSecret,
			Groups:           src.Groups,
			Tenant:           src.Tenant.String(),
			GroupNameFormat:  microsoft.GroupName,
			EmailToLowercase: true,
		}
		return NewExternalCallbackProvider(dst, src.ClientID,
			func(s string, o *microsoft.Config) { o.RedirectURI = s }), nil
	}
}
