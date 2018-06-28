package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"

	"github.com/NetAuth/NetAuth/pkg/client"
	"github.com/NetAuth/Protocol"
)

var (
	nacl         *client.NetAuthClient
	systemShells []string

	pMapFile = flag.String("passwd-file", "/etc/passwd.cache", "Passwd cache to write to")
	gMapFile = flag.String("group-file", "/etc/group.cache", "Group cache to write to")

	indirects = flag.Bool("indirects", true, "Include indirect relationships in the group map")
	minUID    = flag.Int("min-uid", 2000, "Minimum UID number to accept")
	minGID    = flag.Int("min-gid", 2000, "Minimum GID number to accept")

	defHomeDir = flag.String("homedir", "/tmp/{UID}", "Home directory to provide if none is available from NetAuth")
	defShell   = flag.String("shell", "/bin/nologin", "Default shell to use if none is provided in the directory")
)

func init() {
	// Grab a client and identify as nsscached
	var err error
	nacl, err = client.New(nil)
	if err != nil {
		log.Println(err)
		return
	}
	nacl.SetServiceID("nsscached")

	// Grab a listing of system shells and add them here
	bytes, err := ioutil.ReadFile("/etc/shells")
	if err != nil {
		log.Printf("Error reading /etc/shells %s", err)
		return
	}
	shellString := string(bytes[:])
	for _, s := range strings.Split(shellString, "\n") {
		if s != "" {
			systemShells = append(systemShells, s)
		}
	}
	log.Println("The system will accept the following shells")
	for _, s := range systemShells {
		log.Printf("  %s", s)
	}
}

func genPasswd(entList []*Protocol.Entity, grpMap map[string]*Protocol.Group) ([]string, error) {
	// For sanity, sort the users
	sort.Slice(entList, func(i, j int) bool {
		return entList[i].GetNumber() < entList[j].GetNumber()
	})

	// Iterate on the entities and spit out the passwd line.
	lines := []string{}
	for _, e := range entList {
		if int(e.GetNumber()) < *minUID {
			log.Printf("Entity %s has number below min-uid (%d<%d)",
				e.GetID(),
				e.GetNumber(),
				*minUID)
			// Drop this entity due to UID constraints
			continue
		}
		// All entities must have meta data to have a UNIX
		// style account mapping.
		if e.GetMeta() == nil {
			log.Printf("Entity %s is missing metadata", e.GetID())
			continue
		}

		// Determine the primary group number, must be set for
		// UNIX style system logins, as this is not something
		// that can be sanely guessed later.
		var pgid int
		grp, ok := grpMap[e.GetMeta().GetPrimaryGroup()]
		if ok {
			pgid = int(grp.GetNumber())
		} else {
			log.Printf("Entity %s has invalid primary group", e.GetID())
			// Drop this entity due to group constraints
			continue
		}

		// Set the homedir, this can be set to a default if it
		// isn't specified, since this is something that can
		// be done on a system local level.
		homedir := e.GetMeta().GetHome()
		if homedir == "" {
			homedir = strings.Replace(*defHomeDir, "{UID}", e.GetID(), -1)
		}

		// Sanity check the shell
		shell := checkShell(e.GetMeta().GetShell())

		// Create the line for the passwd map
		lines = append(lines, fmt.Sprintf("%s:x:%d:%d:%s:%s:%s",
			e.GetID(),
			e.GetNumber(),
			pgid,
			e.GetMeta().GetGECOS(),
			homedir,
			shell,
		))
	}
	return lines, nil
}

func genGroup(entList []*Protocol.Entity, grpList []*Protocol.Group) ([]string, error) {
	// Iterate on the groups and add entities to them, this is
	// expensive here and on the server, but ultimately requires
	// the server to precompute all group memberships to get any
	// cheaper.  If this proves to be too expensive in prod, then
	// the stopgap is to make this a hosted lookup which happens
	// on an interval that all remote caches populate from.
	groups := make(map[string][]string)
	for _, e := range entList {
		eGroups, err := nacl.ListGroups(e.GetID(), *indirects)
		if err != nil {
			return nil, err
		}
		for _, g := range eGroups {
			groups[g.GetName()] = append(groups[g.GetName()], e.GetID())
		}
	}

	// Keep our sanity and sort the group list
	sort.Slice(grpList, func(i, j int) bool {
		return grpList[i].GetNumber() < grpList[j].GetNumber()
	})

	// Spit out the group file lines
	lines := []string{}
	for _, g := range grpList {
		members := ""
		if gmrs, ok := groups[g.GetName()]; ok {
			members = strings.Join(gmrs[:], ",")
		}
		lines = append(lines, fmt.Sprintf("%s:x:%d:%s",
			g.GetName(),
			g.GetNumber(),
			members,
		))
	}
	return lines, nil
}

// checkShell verifies that the requested shell exists on this system,
// and if it does not it replaces it with a default shell as provided
// by the flags.
func checkShell(shell string) string {
	for _, s := range systemShells {
		if shell == s {
			return s
		}
	}

	// Shell isn't on this system
	return *defShell
}

func writeMap(mapLines []string, location string) error {
	fileString := strings.Join(mapLines, "\n")
	fileString += "\n"
	return ioutil.WriteFile(location, []byte(fileString), 0644)
}

func genIndex(lines []string, indexCol int) map[string]int {
	iMap := make(map[string]int)
	offset := 0

	for _, l := range lines {
		key := strings.Split(l, ":")[indexCol]
		iMap[key] = offset
		offset += len(l) + 1
	}
	return iMap
}

func writeIndex(index map[string]int, location string) error {
	keyList := []string{}
	for k, _ := range index {
		keyList = append(keyList, k)
	}

	sort.Strings(keyList)

	var b bytes.Buffer
	for _, key := range keyList {
		value := index[key]
		fmt.Fprintf(&b, "%s", key)
		fmt.Fprintf(&b, "\x00")
		fmt.Fprintf(&b, "%08d", int64(value))
		for i := 0; i < 32-len(key)-1; i++ {
			fmt.Fprint(&b, "\x00")
		}
		fmt.Fprintf(&b, "\n")
	}
	return ioutil.WriteFile(location, b.Bytes(), 0644)
}

func main() {
	flag.Parse()

	// Get a complete list of entities and all groups
	entList, err := nacl.ListGroupMembers("ALL")
	if err != nil {
		log.Println(err)
	}
	grpList, err := nacl.ListGroups("", false)
	if err != nil {
		log.Println(err)
	}

	// Turn the group list into a map so that we can fetch these
	// back easier later.
	grpMap := make(map[string]*Protocol.Group)
	for _, g := range grpList {
		if int(g.GetNumber()) < *minGID {
			log.Printf("Group %s has number below min-gid (%d<%d)",
				g.GetName(),
				g.GetNumber(),
				*minGID)
			continue
		}
		grpMap[g.GetName()] = g
	}

	passwd, err := genPasswd(entList, grpMap)
	if err != nil {
		log.Println(err)
		return
	}

	group, err := genGroup(entList, grpList)
	if err != nil {
		log.Println(err)
		return
	}

	// Write out the base maps
	if err := writeMap(passwd, *pMapFile); err != nil {
		log.Println(err)
	}
	if err := writeMap(group, *gMapFile); err != nil {
		log.Println(err)
	}

	// Generate the indexes
	passwdixname := genIndex(passwd, 0)
	passwdixuid := genIndex(passwd, 2)
	groupixname := genIndex(group, 0)
	groupixgid := genIndex(group, 2)

	// Write the indexes
	if err := writeIndex(passwdixname, *pMapFile+".ixname"); err != nil {
		log.Println(err)
	}
	if err := writeIndex(passwdixuid, *pMapFile+".ixuid"); err != nil {
		log.Println(err)
	}
	if err := writeIndex(groupixname, *gMapFile+".ixname"); err != nil {
		log.Println(err)
	}
	if err := writeIndex(groupixgid, *gMapFile+".ixgid"); err != nil {
		log.Println(err)
	}
}
