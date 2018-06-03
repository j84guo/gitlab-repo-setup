#!/usr/bin/env python3

import json

from config import gitlab_personal_token, gitlab_root_group, gitlab_user
from http.client import HTTPSConnection

def get_response_body(conn):
    resp = conn.getresponse()
    resp_bytes = resp.read()
    resp_str = str(resp_bytes, "ascii")
    return json.loads(resp_str)

def extract_links(links, repos):
    for repo in repos:
        print(repo["http_url_to_repo"])
        links.append(repo["http_url_to_repo"])

http_verb = "GET"
http_host = "gitlab.com"
http_base_path = "/api/v4"
http_group_path = "{}/groups".format(http_base_path)

headers = {"Private-Token": gitlab_personal_token}

try:
    conn = HTTPSConnection(http_host)
    conn.request(http_verb, "{}?username={}".format(http_group_path, gitlab_user), headers=headers)
    data = get_response_body(conn)
except Exception as e:
    print("Error getting user groups: {}" + e)

# extract group repos
https_links = list()
for group in data:
    if gitlab_root_group in group["full_name"]:
        print("Group name: {}, id: {}".format(group["full_name"], group["id"]))
        conn.request(http_verb, "{}/{}".format(http_group_path, group["id"]), headers=headers)
        data = get_response_body(conn)
        extract_links(https_links, data["projects"])

# generate setup.sh
f = open("setup.sh", "w")
f.write("/usr/bin/env bash\n")

for link in https_links:
    f.write("git clone {}\n".format(link))

f.close()
