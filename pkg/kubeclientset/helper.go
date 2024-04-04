package kubeclientset

import (
	"reflect"
	"slices"

	rbac "k8s.io/api/rbac/v1"
)

// NewRbacRoleBindingCompareFunc returns a CompareWithFn that compares two rbac.RoleBindings.
func NewRbacRoleBindingCompareFunc(eRb *rbac.RoleBinding) CompareWithFn[*rbac.RoleBinding] {
	return func(aRb *rbac.RoleBinding) bool {
		return reflect.DeepEqual(eRb.RoleRef, aRb.RoleRef) &&
			slices.ContainsFunc(eRb.Subjects, func(es rbac.Subject) bool {
				return slices.ContainsFunc(aRb.Subjects, func(as rbac.Subject) bool {
					return reflect.DeepEqual(es, as)
				})
			})
	}
}

// NewRbacClusterRoleBindingCompareFunc returns a CompareWithFn that compares two rbac.ClusterRoleBindings.
func NewRbacClusterRoleBindingCompareFunc(eCrb *rbac.ClusterRoleBinding) CompareWithFn[*rbac.ClusterRoleBinding] {
	return func(aCrb *rbac.ClusterRoleBinding) bool {
		return reflect.DeepEqual(eCrb.RoleRef, aCrb.RoleRef) &&
			slices.ContainsFunc(eCrb.Subjects, func(es rbac.Subject) bool {
				return slices.ContainsFunc(aCrb.Subjects, func(as rbac.Subject) bool {
					return reflect.DeepEqual(es, as)
				})
			})
	}
}

// NewRbacRoleCompareFunc returns a CompareWithFn that compares two rbac.Roles.
func NewRbacRoleCompareFunc(eR *rbac.Role) CompareWithFn[*rbac.Role] {
	return func(aR *rbac.Role) bool {
		return slices.ContainsFunc(eR.Rules, func(er rbac.PolicyRule) bool {
			return slices.ContainsFunc(aR.Rules, func(ar rbac.PolicyRule) bool {
				return reflect.DeepEqual(er, ar)
			})
		})
	}
}

// NewRbacClusterRoleCompareFunc returns a CompareWithFn that compares two rbac.ClusterRoles.
func NewRbacClusterRoleCompareFunc(eCr *rbac.ClusterRole) CompareWithFn[*rbac.ClusterRole] {
	return func(aCr *rbac.ClusterRole) bool {
		return slices.ContainsFunc(eCr.Rules, func(er rbac.PolicyRule) bool {
			return slices.ContainsFunc(aCr.Rules, func(ar rbac.PolicyRule) bool {
				return reflect.DeepEqual(er, ar)
			})
		})
	}
}

// NewRbacRoleAlignFunc returns an AlignWithFn that aligns an existing rbac.Role with the given rbac.Role.
func NewRbacRoleAlignFunc(eR *rbac.Role) AlignWithFn[*rbac.Role] {
	compare := NewRbacRoleCompareFunc(eR)

	return func(aR *rbac.Role) (*rbac.Role, bool, error) {
		if compare(aR) {
			return nil, true, nil
		}

		// Append the existing rules.
		aR.Rules = append(aR.Rules, eR.Rules...)
		return aR, false, nil
	}
}

// NewRbacClusterRoleAlignFunc returns an AlignWithFn that aligns an existing rbac.ClusterRole with the given rbac.ClusterRole.
func NewRbacClusterRoleAlignFunc(eCr *rbac.ClusterRole) AlignWithFn[*rbac.ClusterRole] {
	compare := NewRbacClusterRoleCompareFunc(eCr)

	return func(aCr *rbac.ClusterRole) (*rbac.ClusterRole, bool, error) {
		if compare(aCr) {
			return nil, true, nil
		}

		// Append the existing rules.
		aCr.Rules = append(aCr.Rules, eCr.Rules...)
		return aCr, false, nil
	}
}
