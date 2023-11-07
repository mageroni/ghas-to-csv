# This holds all the things that do stuff for code scanning API

# Imports
from defusedcsv import csv
from . import api_helpers


def list_repo_cs_alerts(api_endpoint, github_pat, repo_name):
    """
    Get a list of all code scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ code scanning alerts on the repository
    """
    url = f"{api_endpoint}/repos/{repo_name}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)

    # iterate code_scanning_alerts and check if the location of the alert is unique, if so, plus add in to one array
    # if not, then add in to the array of duplicates
    # return both arrays

    # create an array of unique alerts
    unique_alerts = []

    # create an array of duplicates
    duplicate_alerts = []

    all_alerts_instances = []

    # iterate through all the alerts
    for alert in code_scanning_alerts:
        # create a flag for the alert
        alert_found = False

        # Get instances of a code scanning alert
        instances_url = f"{api_endpoint}/repos/{repo_name}/code-scanning/alerts/{alert['number']}/instances"
        code_scanning_instances = api_helpers.make_api_call(instances_url, github_pat)
        all_alerts_instances.append(code_scanning_instances)
        
        # iterate through the unique_alerts array
        for unique_alert in unique_alerts:
            # check if the alert is unique
            if alert["most_recent_instance"]["location"]["path"] == unique_alert["most_recent_instance"]["location"]["path"]: # and alert["most_recent_instance"]["location"]["start_line"] == unique_alert["most_recent_instance"]["location"]["start_line"]:
                # add the alert to the duplicate alert array
                duplicate_alerts.append(alert)
                # set the flag to true
                alert_found = True
                # break out of the loop
                break

        # if the alert is not unique, add it to the unique alert array
        if alert_found == False:
            unique_alerts.append(alert)

    # sustitute code_scanning_alerts["instances_url"] with the array of instances
    for i in range(len(code_scanning_alerts)):
        code_scanning_alerts[i]["instances_url"] = all_alerts_instances[i]

    print(f"Found {len(unique_alerts)} Unique alerts and {len(duplicate_alerts)} duplicate code scanning alerts in {repo_name}")
    return code_scanning_alerts


def write_repo_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List of code scanning alerts

    Outputs:
    - CSV file of code scanning alerts
    """

    with open("cs_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "fixed_at",
                "dismissed_by",
                "dismissed_at",
                "dismissed_reason",
                "rule_id",
                "rule_severity",
                "security_severity_level",
                "rule_tags",
                "rule_description",
                "rule_name",
                "tool_name",
                "tool_version",
                "most_recent_instance_ref",
                "most_recent_instance_state",
                "most_recent_instance_sha",
                "most_recent_instance_path",
                "instances_url",
            ]
        )
        for cs in cs_list:
            
            writer.writerow(
                [
                    cs["number"],
                    cs["created_at"],
                    cs["html_url"],
                    cs["state"],
                    cs["fixed_at"],
                    cs["dismissed_at"],
                    cs["dismissed_by"],
                    cs["dismissed_reason"],
                    cs["rule"]["id"],
                    cs["rule"]["severity"],
                    cs["rule"].get("security_severity_level", ""),
                    cs["rule"]["tags"],
                    cs["rule"]["description"],
                    cs["rule"]["name"],
                    cs["tool"]["name"],
                    cs["tool"]["version"],
                    cs["most_recent_instance"]["ref"],
                    cs["most_recent_instance"]["state"],
                    cs["most_recent_instance"]["commit_sha"],
                    cs["most_recent_instance"]["location"]["path"],
                    cs["instances_url"],
                ]
            )


def list_org_cs_alerts(api_endpoint, github_pat, org_name):
    """
    Get a list of all code scanning alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ code scanning alerts on the organization
    """

    url = f"{api_endpoint}/orgs/{org_name}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(code_scanning_alerts)} code scanning alerts in {org_name}")
    return code_scanning_alerts


def write_org_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List of code scanning alerts

    Outputs:
    - CSV file of code scanning alerts
    """

    # Write code scanning alerts to csv file
    with open("cs_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "fixed_at",
                "dismissed_by",
                "dismissed_at",
                "dismissed_reason",
                "rule_id",
                "rule_severity",
                "security_severity_level",
                "rule_tags",
                "rule_description",
                "rule_name",
                "tool_name",
                "tool_version",
                "most_recent_instance_ref",
                "most_recent_instance_state",
                "most_recent_instance_sha",
                "instances_url",
                "repo_name",
                "repo_owner",
                "repo_owner_type",
                "repo_owner_isadmin",
                "repo_url",
                "repo_isfork",
                "repo_isprivate",
            ]
        )
        for cs in cs_list:
            writer.writerow(
                [
                    cs["number"],
                    cs["created_at"],
                    cs["html_url"],
                    cs["state"],
                    cs.get("fixed_at", ""),
                    cs.get("dismissed_by", ""),
                    cs.get("dismissed_at", ""),
                    cs.get("dismissed_reason", ""),
                    cs["rule"]["id"],
                    cs["rule"]["severity"],
                    cs["rule"].get("security_severity_level", ""),
                    cs["rule"]["tags"],
                    cs["rule"]["description"],
                    cs["rule"]["name"],
                    cs["tool"]["name"],
                    cs["tool"]["version"],
                    cs["most_recent_instance"]["ref"],
                    cs["most_recent_instance"]["state"],
                    cs["most_recent_instance"]["commit_sha"],
                    cs["instances_url"],
                    cs["repository"]["full_name"],
                    cs["repository"]["owner"]["login"],
                    cs["repository"]["owner"]["type"],
                    cs["repository"]["owner"]["site_admin"],
                    cs["repository"]["html_url"],
                    str(cs["repository"]["fork"]),
                    str(cs["repository"]["private"]),
                ]
            )


def list_enterprise_server_cs_alerts(api_endpoint, github_pat, repo_list):
    """
    Get a list of all code scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository list in "org/repo" format (from enterprise.get_repo_report)

    Outputs:
    - List of _all_ code scanning alerts in enterprise that PAT user can access

    Notes:
    - Use `ghe-org-admin-promote` to gain ownership of all organizations.
    - Personal repos will not be reported on, as they cannot use code scanning.
    """

    alerts = []
    while True:
        try:
            repo_name = next(repo_list)  # skip the header by putting this up front
            alerts.append(list_repo_cs_alerts(api_endpoint, github_pat, repo_name))
        except StopIteration:
            break
        except Exception as e:
            print(e)
    return alerts


def write_enterprise_server_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.

    Outputs:
    - CSV file of code scanning alerts
    - CSV file of repositories not accessible or without code scanning enabled
    """

    for alert_list in cs_list:
        if type(alert_list) == list:
            with open("cs_list.csv", "a") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "repository",
                        "repo_id",
                        "number",
                        "created_at",
                        "html_url",
                        "state",
                        "fixed_at",
                        "dismissed_by",
                        "dismissed_at",
                        "dismissed_reason",
                        "rule_id",
                        "rule_severity",
                        "security_severity_level",
                        "rule_tags",
                        "rule_description",
                        "rule_name",
                        "tool_name",
                        "tool_version",
                        "most_recent_instance_ref",
                        "most_recent_instance_state",
                        "most_recent_instance_sha",
                        "instances_url",
                    ]
                )
                for cs in alert_list:  # loop through each alert in the list
                    writer.writerow(
                        [
                            cs["repository"]["full_name"],
                            cs["repository"]["id"],
                            cs["number"],
                            cs["created_at"],
                            cs["html_url"],
                            cs["state"],
                            cs.get("fixed_at", ""),
                            cs.get("dismissed_by", ""),
                            cs.get("dismissed_at", ""),
                            cs.get("dismissed_reason", ""),
                            cs["rule"]["id"],
                            cs["rule"]["severity"],
                            cs["rule"].get("security_severity_level", "N/A"),
                            cs["rule"]["tags"],
                            cs["rule"]["description"],
                            cs["rule"]["name"],
                            cs["tool"]["name"],
                            cs["tool"]["version"],
                            cs["most_recent_instance"]["ref"],
                            cs["most_recent_instance"]["state"],
                            cs["most_recent_instance"]["commit_sha"],
                            cs["instances_url"],
                        ]
                    )
        else:
            with open("excluded_repos.csv", "a") as g:
                writer = csv.writer(g)
                writer.writerow([alert_list])


def list_enterprise_cloud_cs_alerts(api_endpoint, github_pat, enterprise_slug):
    """
    Get a list of all code scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope

    Outputs:
    - List of _all_ code scanning alerts in enterprise that PAT user can access
    """

    url = f"{api_endpoint}/enterprises/{enterprise_slug}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(code_scanning_alerts)} code scanning alerts in {enterprise_slug}")
    return code_scanning_alerts


def write_enterprise_cloud_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.

    Outputs:
    - CSV file of code scanning alerts
    - CSV file of repositories not accessible or without code scanning enabled
    """

    with open("cs_list.csv", "a") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "repository",
                "repo_id",
                "number",
                "created_at",
                "html_url",
                "state",
                "fixed_at",
                "dismissed_by",
                "dismissed_at",
                "dismissed_reason",
                "rule_id",
                "rule_severity",
                "security_severity_level",
                "rule_tags",
                "rule_description",
                "rule_name",
                "tool_name",
                "tool_version",
                "most_recent_instance_ref",
                "most_recent_instance_state",
                "most_recent_instance_sha",
                "instances_url",
            ]
        )
        for cs in cs_list:  # loop through each alert in the list
            writer.writerow(
                [
                    cs["repository"]["full_name"],
                    cs["repository"]["id"],
                    cs["number"],
                    cs["created_at"],
                    cs["html_url"],
                    cs["state"],
                    cs.get("fixed_at", ""),
                    cs.get("dismissed_by", ""),
                    cs.get("dismissed_at", ""),
                    cs.get("dismissed_reason", ""),
                    cs["rule"]["id"],
                    cs["rule"]["severity"],
                    cs["rule"].get("security_severity_level", "N/A"),
                    cs["rule"]["tags"],
                    cs["rule"]["description"],
                    cs["rule"]["name"],
                    cs["tool"]["name"],
                    cs["tool"]["version"],
                    cs["most_recent_instance"]["ref"],
                    cs["most_recent_instance"]["state"],
                    cs["most_recent_instance"]["commit_sha"],
                    cs["instances_url"],
                ]
            )
