#!/usr/bin/env python3
from libs.checker import ProxyChecker
from libs.downloader import ProxyDownloader

def main():
    downloader = ProxyDownloader()
    downloader.add("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/socks5.txt")
    downloader.add("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt")

    threads = downloader.run(thread_count=1)
    for t in threads:
        t.join()

    proxies = downloader.get_responses()
    print(f"{len(proxies)} proxies to be eavaluated")

    checker = ProxyChecker(default_timeout=4.0)
    for p in proxies:
        # TODO: at this time, we'll test HTTPS and SOCKS5 only. HTTP are insecure
        checker.add(f"socks5://{p}")
        checker.add(f"https://{p}")

    threads = checker.run(
        thread_count=15,
        timeout=5.0,
        test_host="yahoo.com",
        test_port=443,
        test_use_tls=True,
        http_path="/",
        daemon=True,
    )

    for t in threads:
        t.join()

    print("Valid:", checker.get_valid())
    print("Invalid:", checker.get_invalid())
    print("Pending:", checker.get_pending())


if __name__ == "__main__":
    main()
