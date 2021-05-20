from urllib.request import Request, urlopen
import os
import json
import click as click


def send_request(snyk_token, orgId, projectId):
    headers = {"Content-Type": "application/json", "Authorization": snyk_token}
    request = Request(
        "https://snyk.io/api/v1/org/" + orgId + "/project/" + projectId + "/ignores",
        headers=headers,
    )

    response_body = urlopen(request).read()
    build_snyk_file(response_body)


def build_snyk_file(response_body):
    response_json = json.loads(response_body)
    snyk_info = {}
    vulns = list(response_json.keys())
    for i in range(len(vulns)):
        snyk_info[vulns[i]] = {"reason": response_json[vulns[i]][0]["*"]["reason"]}
        if "expires" in response_json[vulns[i]][0]["*"]:      
            snyk_info[vulns[i]].update(
                {"expires": response_json[vulns[i]][0]["*"]["expires"]}
            )

    snyk_file = """
# Snyk (https://snyk.io) policy file, patches or ignores known vulnerabilities.
version: v1.14.0
language-settings:
ignore:"""

    for vuln_id, info in snyk_info.items():

        normalized_vuln = (
            f"  '{vuln_id}':\n    - '*:'\n      reason: {info['reason']}\n"
        )
        if "expires" in info:
            normalized_vuln += f"      expires: {info['expires']}\n"

        snyk_file += normalized_vuln
    print(snyk_file)
    with open(".snyk", "w") as f:
      f.write(snyk_file)


@click.command()
@click.option('--token', '-t', default=os.getenv("SNYK_TOKEN"), help="Snyk API Token")
@click.option('--orgId', '-o', default=None, help="Snyk Organization ID")
@click.option('--projectId', '-p', default=None, help="Snyk Project ID") 

def main(token, orgid, projectid ):
    send_request(token, orgid, projectid)


if __name__ == "__main__":
    main()
