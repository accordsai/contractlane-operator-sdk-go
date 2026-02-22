package operatorsdk

import "net/url"

func urlEscape(v string) string {
	return url.PathEscape(v)
}
