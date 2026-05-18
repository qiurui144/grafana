package resource

import (
	"context"
	"net/http"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	authlib "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestRequireUserNamespace(t *testing.T) {
	t.Run("returns 401 when no user in context", func(t *testing.T) {
		got := requireUserNamespace(context.Background(), "default")
		require.NotNil(t, got)
		require.Equal(t, int32(http.StatusUnauthorized), got.Code)
	})

	t.Run("allows matching namespace", func(t *testing.T) {
		ctx := authlib.WithAuthInfo(context.Background(), &identity.StaticRequester{
			Type:      authlib.TypeUser,
			Namespace: "default",
		})
		require.Nil(t, requireUserNamespace(ctx, "default"))
	})

	t.Run("rejects cross-namespace request", func(t *testing.T) {
		ctx := authlib.WithAuthInfo(context.Background(), &identity.StaticRequester{
			Type:      authlib.TypeUser,
			Namespace: "org-1",
		})
		got := requireUserNamespace(ctx, "org-2")
		require.NotNil(t, got)
		require.Equal(t, int32(http.StatusForbidden), got.Code)
	})

	t.Run("allows wildcard user into any namespace", func(t *testing.T) {
		ctx := authlib.WithAuthInfo(context.Background(), &identity.StaticRequester{
			Type:      authlib.TypeAccessPolicy,
			Namespace: "*",
		})
		require.Nil(t, requireUserNamespace(ctx, "org-7"))
	})

	t.Run("rejects non-wildcard user on cluster-scoped request", func(t *testing.T) {
		// Cluster-scoped requests have an empty namespace. authlib.NamespaceMatches
		// only allows these for callers with the "*" namespace; any tenant-scoped
		// user must be rejected.
		ctx := authlib.WithAuthInfo(context.Background(), &identity.StaticRequester{
			Type:      authlib.TypeUser,
			Namespace: "default",
		})
		got := requireUserNamespace(ctx, "")
		require.NotNil(t, got)
		require.Equal(t, int32(http.StatusForbidden), got.Code)
	})
}

// newNamespaceTestServer builds a *server with a real KV-backed storage and a
// permissive access client. The four delegated-only RPCs (GetBlob,
// ListManagedObjects, CountManagedObjects, RebuildIndexes) gate on namespace
// first, so search/blob backends are intentionally left unconfigured: a
// request that should be rejected must be rejected before either is consulted.
func newNamespaceTestServer(t *testing.T) *server {
	t.Helper()

	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	kvStore := NewBadgerKV(db)
	store, err := NewKVStorageBackend(KVBackendOptions{KvStore: kvStore})
	require.NoError(t, err)

	srv, err := NewResourceServer(ResourceServerOptions{
		Backend:      store,
		AccessClient: authlib.FixedAccessClient(true),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(stopCtx)
	})
	return srv
}

func ctxAsUserInNamespace(ns string) context.Context {
	return authlib.WithAuthInfo(context.Background(), &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    1,
		UserUID:   "u1",
		Namespace: ns,
	})
}

func TestDelegatedRPCs_RejectCrossNamespace(t *testing.T) {
	srv := newNamespaceTestServer(t)
	userCtx := ctxAsUserInNamespace("org-1")

	t.Run("GetBlob", func(t *testing.T) {
		rsp, err := srv.GetBlob(userCtx, &resourcepb.GetBlobRequest{
			Resource: &resourcepb.ResourceKey{Namespace: "org-2", Group: "g", Resource: "r", Name: "n"},
		})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
	})

	t.Run("ListManagedObjects", func(t *testing.T) {
		rsp, err := srv.ListManagedObjects(userCtx, &resourcepb.ListManagedObjectsRequest{Namespace: "org-2"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
	})

	t.Run("CountManagedObjects", func(t *testing.T) {
		rsp, err := srv.CountManagedObjects(userCtx, &resourcepb.CountManagedObjectsRequest{Namespace: "org-2"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
	})

	t.Run("RebuildIndexes", func(t *testing.T) {
		rsp, err := srv.RebuildIndexes(userCtx, &resourcepb.RebuildIndexesRequest{Namespace: "org-2"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
	})
}

func TestDelegatedRPCs_RejectMissingUser(t *testing.T) {
	srv := newNamespaceTestServer(t)
	ctx := context.Background()

	t.Run("GetBlob", func(t *testing.T) {
		rsp, err := srv.GetBlob(ctx, &resourcepb.GetBlobRequest{
			Resource: &resourcepb.ResourceKey{Namespace: "org-1", Group: "g", Resource: "r", Name: "n"},
		})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusUnauthorized), rsp.Error.Code)
	})

	t.Run("ListManagedObjects", func(t *testing.T) {
		rsp, err := srv.ListManagedObjects(ctx, &resourcepb.ListManagedObjectsRequest{Namespace: "org-1"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusUnauthorized), rsp.Error.Code)
	})

	t.Run("CountManagedObjects", func(t *testing.T) {
		rsp, err := srv.CountManagedObjects(ctx, &resourcepb.CountManagedObjectsRequest{Namespace: "org-1"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusUnauthorized), rsp.Error.Code)
	})

	t.Run("RebuildIndexes", func(t *testing.T) {
		rsp, err := srv.RebuildIndexes(ctx, &resourcepb.RebuildIndexesRequest{Namespace: "org-1"})
		require.NoError(t, err)
		require.NotNil(t, rsp.Error)
		require.Equal(t, int32(http.StatusUnauthorized), rsp.Error.Code)
	})
}

func TestGetBlob_RejectsMissingResourceKey(t *testing.T) {
	srv := newNamespaceTestServer(t)
	rsp, err := srv.GetBlob(ctxAsUserInNamespace("org-1"), &resourcepb.GetBlobRequest{Uid: "blob-uid"})
	require.NoError(t, err)
	require.NotNil(t, rsp.Error)
	require.Equal(t, int32(http.StatusBadRequest), rsp.Error.Code)
}
