#!/usr/bin/env python3

"""
Setup script
- input user credentials
- get OAuth access token
- get user group id's
- for each group, get repos
- write to new bash script
"""

import json
import getpass

from http.client import HTTPSConnection


"""
OauthCredentials
- OAuth 2.0 specification
"""
class OauthCredentials(object):

    def __init__(self, access_token, refresh_token, type, scope, created_at):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.type = type
        self.scope = scope
        self.created_at = created_at

    def __str__(self):
        return "<OauthCredentials object access_token: {}, type: {}>".format(self.access_token, self.type)

    def __repr__(self):
        return self.__str__()


"""
GitLab Group
- unique id
- full name
- repos within the group
"""
class GitlabGroup(object):

    def __init__(self, id, name, full_name, full_path):
        self.id = id
        self.name = name
        self.full_name = full_name
        self.full_path = full_path
        self.repos = list()

    def __str__(self):
        return "<GitlabGroup object id: {}, name: {}, full_name: {}, full_path: {}, repos: {}".format(self.id, self.name, self.full_name, self.full_path, self.repos)

    def __repr__(self):
        return self.__str__()


"""
GitLab Repository
- id
- name
- various url's (ssh, https, web)
"""
class GitlabRepo(object):

    def __init__(self, id, name, ssh_url, https_url, web_url):
        self.id = id
        self.name = name
        self.ssh_url = ssh_url
        self.https_url = https_url
        self.web_url = web_url

    def __str__(self):
        return "<GitlabRepo object id: {}, name: {}, ssh_url: {}, https_url: {} web_url: {}".format(self.id, self.name, self.ssh_url, self.https_url, self.web_url)

    def __repr__(self):
        return self.__str__()


def get_cli_args():
    gl_username = input("GitLab username: ")
    gl_password = getpass.getpass("GitLab password: ")
    gl_group = input("GitLab group: ")
    return gl_username, gl_password, gl_group

def resource_creds_flow(conn, gl_username, gl_password):
    resource_creds_reqs(conn, gl_username, gl_password)
    resp_body = http_resp_json_body(conn)
    try:
        oauth = OauthCredentials(
            resp_body["access_token"],
            resp_body["refresh_token"],
            resp_body["token_type"],
            resp_body["scope"],
            resp_body["created_at"]
        )
        return oauth
    except Exception as e:
        print("Error obtaining OAuth access token: {}".format(repr(e)))

def resource_creds_reqs(conn, gl_username, gl_password):
    creds = {
        "grant_type": "password",
        "username": gl_username,
        "password": gl_password
    }
    body = json.dumps(creds)
    reqs_headers = {
        "Content-Type": "application/json"
    }
    conn.request("POST", "/oauth/token", headers=reqs_headers, body=body)

def http_resp_json_body(conn):
    try:
        resp = conn.getresponse()
        resp_bytes = resp.read()
        resp_str = str(resp_bytes, "ascii")
        body = json.loads(resp_str)
        return body
    except Exception as e:
        print("Error contacting GitLab API: {}".format(repr(e)))

def user_groups_reqs(conn, gl_username, oauth):
    reqs_headers = {
        "Authorization": "Bearer {}".format(oauth.access_token)
    }
    path = "/api/v4/groups?username={}".format(gl_username)
    conn.request("GET", path, headers=reqs_headers)

def get_user_groups(conn, gl_username, oauth):
    user_groups_reqs(conn, gl_username, oauth)
    resp_body = http_resp_json_body(conn)
    return resp_body

def get_relevant_user_groups(conn, gl_username, gl_group, oauth):
    all_groups = get_user_groups(conn, gl_username, oauth)
    groups = [GitlabGroup(g["id"], g["name"], g["full_name"], g["full_path"]) for g in all_groups if is_subgroup(gl_group, g["full_name"])]
    return groups

def is_subgroup(root, full_name):
    return full_name == root or root in full_name and not full_name.endswith(root)

def load_group_repos(conn, groups, oauth):
    for g in groups:
        g.repos = get_group_repos(conn, g.id, oauth)

def get_group_repos(conn, g_id, oauth):
    group_repos_reqs(conn, g_id, oauth)
    resp_body = http_resp_json_body(conn)
    return [GitlabRepo(r["id"], r["name"], r["ssh_url_to_repo"], r["http_url_to_repo"], r["web_url"]) for r in resp_body["projects"]]

def group_repos_reqs(conn, g_id, oauth):
    reqs_headers = {
        "Authorization": "Bearer {}".format(oauth.access_token)
    }
    path = "/api/v4/groups/{}".format(g_id)
    conn.request("GET", path, headers=reqs_headers)

def generate_bash_script(groups, gl_group):
    f = open("setup.sh", "w")

    f.write("/usr/bin/env bash\n\n")
    f.write("cd ~\n\n")

    for g in groups:
        f.write("mkdir -p {}\n".format(g.full_path))
        for r in g.repos:
            f.write("git clone {}\n".format(r.https_url))
            f.write("mv {} {}\n".format(r.name, g.full_path))
        f.write("\n")

    f.close()


if __name__ == "__main__":

    gl_username, gl_password, gl_group = get_cli_args()
    conn = HTTPSConnection("gitlab.com")

    print("Obtaining OAuth access token...")
    oauth = resource_creds_flow(conn, gl_username, gl_password)
    print("...done\n")

    print("Fetching sub-groups of {}...".format(gl_group))
    groups = get_relevant_user_groups(conn, gl_username, gl_group, oauth)
    print("...done\n")

    print("Loading group repositories...")
    load_group_repos(conn, groups, oauth)
    print("...done\n")

    print("Generating Git script setup.sh...")
    generate_bash_script(groups, gl_group)
    print("...done\n")

    print("To setup git repositories in ~/{} run ./setup.sh".format(gl_group))
