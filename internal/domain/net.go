package domain

import "strconv"

func joinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
