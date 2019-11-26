package main

import (
	"context"
	"strings"

	"github.com/MiLk/nsscache-go/cache"
	"github.com/MiLk/nsscache-go/source"
	"github.com/hashicorp/go-hclog"

	pb "github.com/netauth/protocol"
	"github.com/netauth/netauth/pkg/netauth"

	// We need a token cache available, even if no tokens will be
	// issued.
	_ "github.com/netauth/netauth/pkg/netauth/memory"
)

// A NetAuthCacheFiller satisfies the cache filler interface and uses
// NetAuth as the data source.
type NetAuthCacheFiller struct {
	entities map[string]*pb.Entity
	groups   map[string]*pb.Group
	members  map[string][]string
	pgroups  map[string]uint32

	// The MinUID and MinGID specify the numeric lower bound for
	// remote values to be loaded into the system.  These values
	// should be set with a decent amount of headroom above the
	// local namespace on the machine.  A default of 2000 is
	// recommended for both.
	MinUID int32
	MinGID int32

	// The DefaultShell is a mix between convenience and security.
	// On a secure system this will be /bin/false or
	// /sbin/nologin, whereas on a convenient system this will be
	// /bin/sh or /bin/bash.  This shell will be substituted in if
	// the shell specified for a user isn't present in the list of
	// AllowedShells.
	DefaultShell string

	// This is the list of shells that are permitted on a given
	// host.  This list should normally be populated with the list
	// from /etc/shells.
	AllowedShells []string

	// The DefaultHome is the location for user files to be
	// specified in the passwd map.  This location can include the
	// magic token {UID} which will be replaced with the entity ID
	// during templating if no other home directory is specified.
	DefaultHome string

	c *netauth.Client

	l hclog.Logger
}

// NewCacheFiller returns an interface that can be used to fill caches
// using the libnss library.
func NewCacheFiller(minuid, mingid int32, defshell, defhome string, shells []string) (source.Source, error) {
	x := NetAuthCacheFiller{
		entities: make(map[string]*pb.Entity),
		groups:   make(map[string]*pb.Group),
		members:  make(map[string][]string),
		pgroups:  make(map[string]uint32),

		MinUID: minuid,
		MinGID: mingid,

		DefaultShell:  defshell,
		AllowedShells: shells,

		DefaultHome: defhome,

		l: hclog.L().Named("cachefiller"),
	}

	ctx := context.Background()

	c, err := netauth.New()
	if err != nil {
		x.l.Error("Error during client initialization", "error", err)
		return nil, err
	}
	c.SetServiceName("nsscache")
	x.c = c

	if err := x.findGroups(ctx); err != nil {
		return nil, err
	}
	if err := x.findEntities(ctx); err != nil {
		return nil, err
	}
	if err := x.findMembers(ctx); err != nil {
		return nil, err
	}

	return &x, nil
}

// FillShadowCache fills the shadow cache.  Since NetAuth doesn't
// provide a way to exfiltrate the secret hashes, the shadow cache
// just gets filled with *'s.
func (nc *NetAuthCacheFiller) FillShadowCache(c *cache.Cache) error {
	for i := range nc.entities {
		c.Add(&cache.ShadowEntry{Name: nc.entities[i].GetID(), Passwd: "*"})
	}
	return nil
}

// FillGroupCache fills in the group cache using information from
// NetAuth.
func (nc *NetAuthCacheFiller) FillGroupCache(c *cache.Cache) error {
	for i := range nc.groups {
		c.Add(&cache.GroupEntry{
			Name:   nc.groups[i].GetName(),
			Passwd: "*",
			GID:    uint32(nc.groups[i].GetNumber()),
			Mem:    nc.members[nc.groups[i].GetName()],
		})
	}
	return nil
}

// FillPasswdCache fills in the cache for normal users.  This function
// makes some choices about where home folders are located and what to
// fill in for the user's shell if the values aren't fully specified.
func (nc *NetAuthCacheFiller) FillPasswdCache(c *cache.Cache) error {
	for i := range nc.entities {
		c.Add(&cache.PasswdEntry{
			Name:   nc.entities[i].GetID(),
			Passwd: "*",
			UID:    uint32(nc.entities[i].GetNumber()),
			GID:    nc.pgroups[nc.entities[i].GetMeta().GetPrimaryGroup()],
			Dir:    nc.entities[i].GetMeta().GetHome(),
			Shell:  nc.entities[i].GetMeta().GetShell(),
		})
	}
	return nil
}

// findGroups fetches a list of groups from the server and discards
// groups with a GID below the specified minimum.  The groups are
// indexed by name targeting both the group struct and the number.
func (nc *NetAuthCacheFiller) findGroups(ctx context.Context) error {
	grps, err := nc.c.GroupSearch(ctx, "*")
	if err != nil {
		return err
	}
	for i := range grps {
		if grps[i].GetNumber() < nc.MinGID {
			// Group number is too low, continue without
			// this one.
			nc.l.Warn("Ignoring group, GID is below cutoff",
				"group", grps[i].GetName(),
				"limit", nc.MinGID,
				"gid", grps[i].GetNumber())
			continue
		}
		nc.groups[grps[i].GetName()] = grps[i]
		nc.pgroups[grps[i].GetName()] = uint32(grps[i].GetNumber())
	}
	return nil
}

// findEntities fetches a list of entities from the server and
// discards entities with a UID below the specicified minimum or with
// an invalid primary group.  Then, the default shell is checked
// against the shells on the system and optionally replaced with the
// default.  Finally, the home directory is checked and optionally
// replaced with the default.
func (nc *NetAuthCacheFiller) findEntities(ctx context.Context) error {
	ents, err := nc.c.EntitySearch(ctx, "*")
	if err != nil {
		return err
	}

	for i := range ents {
		if ents[i].GetNumber() < nc.MinUID {
			// The uidNumber was too low, continue without
			// this one.
			nc.l.Warn("Ignoring entity, UID is below cutoff",
				"entity", ents[i].GetID(),
				"limit", nc.MinUID,
				"uid", ents[i].GetNumber())
			continue
		}
		if _, ok := nc.pgroups[ents[i].GetMeta().GetPrimaryGroup()]; !ok {
			// The primary group was invalid, continue
			// without this one.
			nc.l.Warn("Ignoring entity, Primary Group is invalid",
				"entity", ents[i].GetID())
			continue
		}
		if nc.hasBadShell(ents[i].GetMeta().GetShell()) {
			ents[i].Meta.Shell = &nc.DefaultShell
		}
		if ents[i].GetMeta().GetHome() == "" {
			t := strings.Replace(nc.DefaultHome, "{UID}", ents[i].GetID(), -1)
			ents[i].Meta.Home = &t
		}
		nc.entities[ents[i].GetID()] = ents[i]
	}
	return nil
}

// findMembers works out from the groups that are valid on the system
// the effective memberships.  This function is quite expensive to
// call, so if this is causing performance problems in your
// environment its recommended to have a central point compute the
// cache files and distribute them securely.
func (nc *NetAuthCacheFiller) findMembers(ctx context.Context) error {
	tmp := make(map[string]map[string]struct{})
	for g := range nc.groups {
		tmp[g] = make(map[string]struct{})
		members, err := nc.c.GroupMembers(ctx, g)
		if err != nil {
			return err
		}
		for i := range members {
			if _, ok := nc.entities[members[i].GetID()]; !ok {
				// This entity has already been
				// discarded for some reason.
				continue
			}
			tmp[g][members[i].GetID()] = struct{}{}
		}
	}

	// Add every entity to its primary group.  This isn't
	// necessarily required by the specification, but it does
	// clear up a lot of really confusing corner cases, and is
	// generally what people expect.
	for i := range nc.entities {
		tmp[nc.entities[i].GetMeta().GetPrimaryGroup()][nc.entities[i].GetID()] = struct{}{}
	}

	for g, mem := range tmp {
		nc.members[g] = make([]string, len(tmp[g]))
		idx := 0
		for i := range mem {
			nc.members[g][idx] = i
			idx++
		}
	}
	return nil
}

// hasBadShell returns true if the provided test shell is not present
// in the list of AllowedShells for this system.
func (nc *NetAuthCacheFiller) hasBadShell(s string) bool {
	for i := range nc.AllowedShells {
		if nc.AllowedShells[i] == s {
			return false
		}
	}
	return true
}
