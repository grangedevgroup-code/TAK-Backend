package main

import (
	"fmt"
	"strings"
	"time"
)

func cmdCluster(a *args) error {
	switch strings.ToLower(a.arg(0)) {
	case "", "status":
		return withClient(a, func(c *client) error {
			var st struct {
				Enabled bool   `json:"enabled"`
				URL     string `json:"url"`
				Nodes   []struct {
					Name     string    `json:"name"`
					URL      string    `json:"url"`
					State    string    `json:"state"`
					Error    string    `json:"error"`
					Since    time.Time `json:"since"`
					Synced   bool      `json:"synced"`
					Devices  int       `json:"devices"`
					Received uint64    `json:"received"`
					Sent     uint64    `json:"sent"`
				} `json:"nodes"`
			}
			if err := c.call("GET", "/api/cluster", nil, &st); err != nil {
				return err
			}
			if !st.Enabled {
				fmt.Println("This server is not in a cluster. Start one with: golangtakserver cluster invite")
				return nil
			}
			fmt.Printf("This node: %s\n", st.URL)
			if len(st.Nodes) == 0 {
				fmt.Println("No other nodes are connected yet.")
			}
			for _, n := range st.Nodes {
				state := n.State
				if n.State == "connected" && !n.Synced {
					state = "syncing"
				}
				line := fmt.Sprintf("  %-28s %-11s %s", n.URL, state, n.Name)
				if n.State == "connected" {
					line += fmt.Sprintf("  devices %d  messages in %d out %d", n.Devices, n.Received, n.Sent)
				}
				if n.Error != "" && n.State != "connected" {
					line += "  (" + n.Error + ")"
				}
				fmt.Println(line)
			}
			return nil
		})
	case "invite":
		return withClient(a, func(c *client) error {
			var res struct {
				Code string `json:"code"`
			}
			if err := c.call("POST", "/api/cluster/invite", map[string]any{}, &res); err != nil {
				return err
			}
			fmt.Printf("Cluster code:\n\n%s\n\nOn the new server run:\n  golangtakserver cluster join CODE\nThe code contains this cluster's certificate authority. Send it privately, and use it on a fresh server: the new node takes the cluster's users, devices, missions and files.\n", res.Code)
			return nil
		})
	case "join":
		code := a.arg(1)
		if code == "" {
			return errUsage
		}
		return withClient(a, func(c *client) error {
			if err := c.call("POST", "/api/cluster/join", map[string]any{"code": code}, nil); err != nil {
				return err
			}
			fmt.Println("Joined. The server restarts with the cluster's certificate authority and copies the cluster's data. Check it with: golangtakserver cluster status")
			return nil
		})
	case "leave":
		return withClient(a, func(c *client) error {
			if err := c.call("POST", "/api/cluster/leave", map[string]any{}, nil); err != nil {
				return err
			}
			fmt.Println("This server left the cluster. Its data and certificates stay as they are.")
			return nil
		})
	}
	return errUsage
}
