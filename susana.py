import sys

import pclient

PROXIES_NAME = "proxies.txt"
ACCOUNTS_NAME = "accounts.txt"
blog = "http://aminoapps.com/p/51cgck"


if __name__ == '__main__':
    sys.setrecursionlimit(10000)
    for i in range(1000):
        pclient.ModeratorProcessor(PROXIES_NAME, ACCOUNTS_NAME, blog).admin()
