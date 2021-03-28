import base64
import json
import os
import socket
import time
from base64 import b64decode
from urllib.parse import urlsplit
from urllib.request import urlopen

import requests
import socks

WEB_SPEED = 5
DOWNLOAD_SPEED = 150000
TIME_LIMIT = 5
WAIT_RESTART = 10
template = {
    "vmess": {
        "policy": {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "log": {
            "access": "",
            "error": "",
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 2333,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "allowTransparent": False
                }
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "udp": False,
                    "allowTransparent": False
                }
            },
            {
                "tag": "api",
                "port": 61243,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "udp": False,
                    "address": "127.0.0.1",
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": "132.145.111.134",
                            "port": 443,
                            "users": [
                                {
                                    "id": "bae399d4-13a4-46a3-b144-4af2c0004c2e",
                                    "alterId": 64,
                                    "email": "t@t.tt",
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "allowInsecure": False,
                        "serverName": "132.145.111.134"
                    },
                    "wsSettings": {
                        "path": "/v2ray",
                        "headers": {
                            "Host": "132.145.111.134"
                        }
                    }
                },
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                }
            }
        ],
        "stats": {},
        "api": {
            "tag": "api",
            "services": [
                "StatsService"
            ]
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:example-example.com",
                        "domain:example-example2.com"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:cn"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:private",
                        "geoip:cn"
                    ]
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }
    },
    "shadowsocks": {
        "policy": {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "log": {
            "access": "",
            "error": "",
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 2333,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "allowTransparent": False
                }
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "udp": False,
                    "allowTransparent": False
                }
            },
            {
                "tag": "api",
                "port": 61243,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "udp": False,
                    "address": "127.0.0.1",
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": "185.38.148.228",
                            "method": "aes-256-gcm",
                            "ota": False,
                            "password": "8n6pwAcrrv2pj6tFY2p3TbQ6",
                            "port": 33992,
                            "level": 1
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp"
                },
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                }
            }
        ],
        "stats": {},
        "api": {
            "tag": "api",
            "services": [
                "StatsService"
            ]
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:example-example.com",
                        "domain:example-example2.com"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:cn"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:private",
                        "geoip:cn"
                    ]
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }
    },
    "trojan": {
        "policy": {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "log": {
            "access": "",
            "error": "",
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 2333,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "allowTransparent": False
                }
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "udp": False,
                    "allowTransparent": False
                }
            },
            {
                "tag": "api",
                "port": 61243,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "udp": False,
                    "address": "127.0.0.1",
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": "pro-us1-1.sstr-api.xyz",
                            "method": "chacha20",
                            "ota": False,
                            "password": "W3ADSjTHjxN3Nt28WC",
                            "port": 443,
                            "level": 1
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "allowInsecure": False
                    }
                },
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                }
            }
        ],
        "stats": {},
        "api": {
            "tag": "api",
            "services": [
                "StatsService"
            ]
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:example-example.com",
                        "domain:example-example2.com"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:cn"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:private",
                        "geoip:cn"
                    ]
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }
    },
    "vless": {
        "policy": {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "log": {
            "access": "",
            "error": "",
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 2333,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "allowTransparent": False
                }
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                },
                "settings": {
                    "udp": False,
                    "allowTransparent": False
                }
            },
            {
                "tag": "api",
                "port": 61243,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "udp": False,
                    "address": "127.0.0.1",
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "198.41.208.0",
                            "port": 443,
                            "users": [
                                {
                                    "id": "f82b5622-3d18-4318-b3c6-c6367baa2167",
                                    "alterId": 0,
                                    "email": "t@t.tt",
                                    "security": "auto",
                                    "encryption": "none",
                                    "flow": ""
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "allowInsecure": False,
                        "serverName": "nl1.free2222.xyz"
                    },
                    "wsSettings": {
                        "path": "/ray",
                        "headers": {
                            "Host": "nl1.free2222.xyz"
                        }
                    }
                },
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                }
            }
        ],
        "stats": {},
        "api": {
            "tag": "api",
            "services": [
                "StatsService"
            ]
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:example-example.com",
                        "domain:example-example2.com"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:cn"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:private",
                        "geoip:cn"
                    ]
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }
    }
}


def read_vmess(splited_url):
    try:
        url_netloc = splited_url.netloc
        json_content = json.loads(b64decode(url_netloc).decode('utf-8'))
        config = {"protocol": "vmess",
                  "settings": {
                      "vnext": [
                          {
                              "address": json_content.get('add'),
                              "port": int(json_content.get('port')),
                              "users": [
                                  {
                                      "id": json_content.get('id'),
                                      "alterId": int(json_content.get('aid')),
                                      "email": "t@t.tt",
                                      "security": "auto"
                                  }
                              ]
                          }
                      ]
                  },
                  "streamSettings": {
                      "network": json_content.get('net'),
                      "security": "tls",
                      "tlsSettings": {
                          "allowInsecure": False,
                          "serverName": json_content.get('host')
                      },
                      "wsSettings": {
                          "path": json_content.get('path'),
                          "headers": {
                              "Host": json_content.get('host')
                          }
                      }
                  }, }
        return config
    except Exception as e:
        print(e)
        return None


def read_ss(splited_url):
    try:
        url_netloc = splited_url.netloc
        # 两种不同的编码方式
        if '@' in url_netloc:
            method_password = url_netloc.split('@')[0]
            method_password_decode = b64decode(method_password).decode('utf-8')
            method = method_password_decode.split(':')[0]
            password = method_password_decode.split(':')[1]
            add_port = url_netloc.split('@')[1]
            add = add_port.split(':')[0]
            port = int(add_port.split(':')[1])
        else:
            url_netloc = b64decode(url_netloc).decode('utf-8')
            method_password = url_netloc.split('@')[0]
            method = method_password.split(':')[0]
            password = method_password.split(':')[1]
            add_port = url_netloc.split('@')[1]
            add = add_port.split(':')[0]
            port = add_port.split(':')[1]
        config = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": add,
                        "method": method,
                        "ota": False,
                        "password": password,
                        "port": int(port),
                        "level": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp"
            },
        }
        return config
    except Exception as e:
        print(e)
        return None


def read_trojan(splited_url):
    try:
        url_netloc = splited_url.netloc
        config = {"protocol": "trojan",
                  "settings": {
                      "servers": [
                          {
                              "address": splited_url.hostname,
                              "method": "chacha20",
                              "ota": False,
                              "password": url_netloc.split('@')[0],
                              "port": int(url_netloc.split(':')[1]),
                              "level": 1
                          }
                      ]
                  },
                  "streamSettings": {
                      "network": "tcp",
                      "security": "tls",
                      "tlsSettings": {
                          "allowInsecure": False
                      }
                  }, }
        return config
    except Exception as e:
        print(e)
        return None


def read_vless(splited_url):
    try:
        query = splited_url.query.replace('%f', '/')
        params = query.split('&')
        params_json = {}
        for param in params:
            params_json[param.split('=')[0]] = param.split('=')[1]

        config = {"protocol": "vless",
                  "settings": {
                      "vnext": [
                          {
                              "address": splited_url.hostname,
                              "port": int(splited_url.port),
                              "users": [
                                  {
                                      "id": splited_url.username,
                                      "alterId": 64,
                                      "email": "t@t.tt",
                                      "security": "auto"
                                  }
                              ]
                          }
                      ]
                  },
                  "streamSettings": {
                      "network": params_json.get('type'),
                      "security": params_json.get('security'),
                      "tlsSettings": {
                          "allowInsecure": False,
                          "serverName": params_json.get('host')
                      },
                      "wsSettings": {
                          "path": params_json.get('path'),
                          "headers": {
                              "Host": params_json.get('host')
                          }
                      }
                  }, }
        return config
    except Exception as e:
        print(e)
        return None


def get_share_links(return_content):
    print('call method get_share_links')
    share_links = b64decode(return_content).decode('utf-8').splitlines()
    return share_links


def read_content(share_links) -> dict:
    print('call method read_content')
    link_with_config = {}
    for share_link in share_links:
        url_split = urlsplit(share_link)
        protocol = url_split.scheme
        if protocol == 'vmess' and read_vmess(url_split):
            link_with_config[share_link] = read_vmess(url_split)
        elif protocol == 'ss' and read_ss(url_split):
            link_with_config[share_link] = read_ss(url_split)
        elif protocol == 'trojan' and read_trojan(url_split):
            link_with_config[share_link] = read_trojan(url_split)
        elif protocol == 'vless' and read_vless(url_split):
            link_with_config[share_link] = read_vless(url_split)
        else:
            print('protocol not supported')
    return link_with_config


def set_config(config: dict, config_file='/volume1/docker/v2ray/config.json'):
    print('set config and restart v2ray')
    if config:
        protocol = config.get('protocol')
        temp = template.get(protocol)
        outbounds = temp.get('outbounds')
        proxy_tag = outbounds[0]
        proxy_tag['protocol'] = protocol
        proxy_tag['settings'] = config.get('settings')
        proxy_tag['streamSettings'] = config.get('streamSettings')
        output = json.dumps(temp, indent=True, sort_keys=True)
        with open(config_file, 'w') as f:
            f.write(output)
        os.popen('docker restart v2ray')
        time.sleep(WAIT_RESTART)


def get_web_speed():
    print('testing web speed ...')
    start = time.time()
    socks.setdefaultproxy(socks.SOCKS5, '127.0.0.1', 2333)
    socket.socket = socks.socksocket
    url = 'http://www.google.com'
    try:
        requests.get(url, timeout=TIME_LIMIT)
    except Exception as e:
        print(e)
        return 10
    end = time.time()
    return end - start


def get_download_speed():
    print('testing download speed ...')
    cmd = 'curl -m' + str(
        TIME_LIMIT) + ' -x socks5://127.0.0.1:2333 -Lo /dev/null -skw "%{speed_download}\n" http://cachefly.cachefly.net/10mb.test'
    p = os.popen(cmd)
    result = p.readlines()
    if isinstance(result, list):
        download_speed = result[0].replace('\n', '')
        return float(download_speed)
    return 10


def get_best_config(share_links) -> dict:
    print('call method get_best_config')
    link_with_config = read_content(share_links)
    best_links = {}
    for link, config in link_with_config.items():
        set_config(config)
        web_speed = get_web_speed()
        if web_speed < WEB_SPEED:
            print(web_speed)
            download_speed = get_download_speed()
            if download_speed > DOWNLOAD_SPEED:
                print(download_speed)
                print('\033[92m' + 'found a fast link, add to best_links' + link + '\033[0m')
                best_links[link] = download_speed
    return best_links


def gen_subscribe(urls, n):
    print('call method gen_subscribe')
    share_links = []
    for url in urls:
        share_links += get_share_links(get_return_content(url))

    best_links = get_best_config(share_links)
    sorted_links = sorted(best_links.items(), key=lambda item: item[1], reverse=True)[:n]

    link_str = '\n'.join(link[0] for link in sorted_links)
    link_b64 = base64.b64encode(link_str.encode('utf-8'))
    return link_b64


def set_default_v2ray():
    print('call method set_default_v2ray')
    bwg = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": "104.128.91.5",
                    "port": 42681,
                    "users": [
                        {
                            "id": "b666829d-34b7-4d97-b281-9e6049a6539f",
                            "alterId": 0,
                            "email": "t@t.tt",
                            "security": "auto"
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": "tcp"
        },
    }
    set_config(bwg)


def get_return_content(url):
    print('call method get_return_content')
    if 'api.github.com' in url:
        tmp = requests.get(url).json().get('content')
        return b64decode(tmp).decode('utf-8')
    return urlopen(url).read()


def main():
    print('call method main')
    set_default_v2ray()
    urls = [
        'https://api.github.com/repos/adiwzx/freenode/contents/adispeed.txt',
        'https://api.github.com/repos/freefq/free/contents/v2',
        'https://iwxf.netlify.app'
    ]
    c = gen_subscribe(urls, 10)
    print(c)
    with open('/volume1/docker/nginx/v2.txt', 'w') as f:
        f.write(str(c, encoding='utf-8'))
    # restart nginx
    os.popen('docker restart nginx1')


if __name__ == '__main__':
    main()
