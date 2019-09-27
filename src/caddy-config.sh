#local email=$(((RANDOM << 22)))
case $v2ray_transport in
4)
	if [[ $is_path ]]; then
		cat >/etc/caddy/sites/$domain <<-EOF
$domain {
    tls /etc/ssl/caddy/${zone_domain}.crt /etc/tls/${zone_domain}.key
    gzip
	timeouts none
    proxy / $proxy_site {
        except /${path}
    }
    proxy /${path} 127.0.0.1:${v2ray_port} {
        without /${path}
        websocket
    }
}
import sites/*
		EOF
	else
		cat >/etc/caddy/sites/$domain <<-EOF
$domain {
    tls /etc/ssl/caddy/${zone_domain}.crt /etc/tls/${zone_domain}.key
	timeouts none
	proxy / 127.0.0.1:${v2ray_port} {
		websocket
	}
}
import sites/*
		EOF
	fi
	;;
5)
	if [[ $is_path ]]; then
		cat >/etc/caddy/sites/$domain <<-EOF
$domain {
    tls /etc/ssl/caddy/${zone_domain}.crt /etc/tls/${zone_domain}.key
    gzip
	timeouts none
    proxy / $proxy_site {
        except /${path}
    }
    proxy /${path} https://127.0.0.1:${v2ray_port} {
        header_upstream Host {host}
		header_upstream X-Forwarded-Proto {scheme}
		insecure_skip_verify
    }
}
import sites/*
		EOF
	else
		cat >/etc/caddy/sites/$domain <<-EOF
$domain {
    tls /etc/ssl/caddy/${zone_domain}.crt /etc/tls/${zone_domain}.key
	timeouts none
	proxy / https://127.0.0.1:${v2ray_port} {
        header_upstream Host {host}
		header_upstream X-Forwarded-Proto {scheme}
		insecure_skip_verify
	}
}
import sites/*
		EOF
	fi
	;;

esac
