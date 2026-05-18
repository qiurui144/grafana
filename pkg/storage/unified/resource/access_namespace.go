package resource

import (
	"context"
	"net/http"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// requireUserNamespace is a minimal, low-cost gate that delegated-only RPCs
// can call before doing per-tenant work. It returns:
//
//   - 401 ErrorResult when the request has no AuthInfo (the caller forgot to
//     stamp identity in ctx),
//   - 403 ErrorResult when the user's namespace does not match the requested
//     namespace and is not the wildcard "*",
//   - nil when the caller may proceed.
//
// This is not a substitute for resource-level access.Check; it only catches
// the cross-tenant case (a user authenticated for one namespace asking for
// data in another) which the per-method NOTE warns about.
func requireUserNamespace(ctx context.Context, namespace string) *resourcepb.ErrorResult {
	user, ok := claims.AuthInfoFrom(ctx)
	if !ok || user == nil {
		return &resourcepb.ErrorResult{
			Message: "no user found in context",
			Code:    http.StatusUnauthorized,
		}
	}
	if !claims.NamespaceMatches(user.GetNamespace(), namespace) {
		return &resourcepb.ErrorResult{
			Message: "namespace mismatch",
			Code:    http.StatusForbidden,
		}
	}
	return nil
}
