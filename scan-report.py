#!/usr/bin/env python3

import ssl

ssl._create_default_https_context = ssl._create_unverified_context
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import json
import os
import pprint
import re
import time

import requests
import yaml
from fpdf import FPDF


class PDF(FPDF):
    def __init__(self, title, banner, id, requested, database_time, vulnerabilities):
        super().__init__()
        self.title = title
        self.banner = banner
        self.id = id
        self.requested = requested
        self.database_time = database_time
        self.vulnerabilities = vulnerabilities

    def header(self):
        # Logo
        self.image(self.banner, None, None, 190, 0)
        # Arial bold 15
        self.set_font("Arial", "B", 15)
        # Move to the right
        # self.cell(20)
        # Title
        self.cell(160, 10, "Scan Report: " + self.title, 0, 0, "C")
        # Line break
        self.ln(self.font_size * 2.5)
        # Arial bold 12
        self.set_font("Arial", "B", 12)
        # Scan Summary
        self.cell(160, self.font_size, "Scan ID: " + self.id, 0, 1)
        self.cell(160, self.font_size, "Scan requested at: " + self.requested, 0, 1)
        self.cell(160, self.font_size, "Database time: " + self.database_time, 0, 1)
        self.cell(160, self.font_size, "Vulnerabilities: " + self.vulnerabilities, 0, 1)
        # Line break
        self.ln(self.font_size * 1.5)

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font("Arial", "I", 8)
        # Page number
        self.cell(0, 10, "Page " + str(self.page_no()) + "/{nb}", 0, 0, "C")


def dssc_auth(cfg):
    ###Authenticates to Smart Check###

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/sessions"
    data = {
        "user": {"userid": cfg["dssc"]["username"], "password": cfg["dssc"]["password"]}
    }

    post_header = {
        "Content-type": "application/json",
        "x-argus-api-version": "2017-10-16",
    }
    response = requests.post(
        url, data=json.dumps(data), headers=post_header, verify=False
    )
    response = response.json()

    if "message" in response:
        print("Authentication response: " + response["message"])
        if response["message"] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or", "SmartCheck not available")

    return response["token"]


def dssc_latest_scan(cfg, token):
    ###Queries the latest scan of the given image###

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/scans?limit=500"
    data = {}
    post_header = {"Content-type": content_type, "authorization": "Bearer " + token}
    response = requests.get(
        url, data=json.dumps(data), headers=post_header, verify=False
    ).json()

    scan_id = ""
    scan_time = "2000-01-1T00:00:00Z"
    for scan in response.get("scans", {}):
        if (
            scan.get("source", {}).get("repository", "") == cfg["repository"]["name"]
        ) and (
            scan.get("source", {}).get("tag", "") == str(cfg["repository"]["image_tag"])
        ):
            if scan["details"]["updated"] > scan_time:
                scan_time = scan["details"]["updated"]
                scan_id = scan["id"]

    if scan_id == "":
        raise ValueError("Scan not found")

    return scan_id


def dssc_scan(cfg, scan_id, token):
    ###Queries the scan of the given image from Smart Check###

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    url = "https://" + cfg["dssc"]["service"] + "/api/scans/" + scan_id
    data = {}
    post_header = {"Content-type": content_type, "authorization": "Bearer " + token}
    response = requests.get(
        url, data=json.dumps(data), headers=post_header, verify=False
    ).json()

    # query vulnerability database update time
    scanners_list = response["findings"].get("scanners", {})
    database_time = scanners_list.get("vulnerabilities", {}).get("updated", {})
    scan_requested_time = response["details"].get("requested", {})

    # iterate layers
    result_list = response["details"].get("results", {})

    vulns = {}
    vul_count_defcon1 = 0
    vul_count_critical = 0
    vul_count_high = 0
    vul_count_medium = 0

    for result in result_list:
        if "vulnerabilities" in result:

            url = (
                "https://"
                + cfg["dssc"]["service"]
                + result.get("vulnerabilities", {})
                + "?limit=10000"
            )
            data = {}
            post_header = {
                "Content-type": content_type,
                "authorization": "Bearer " + token,
            }
            response_layer = requests.get(
                url, data=json.dumps(data), headers=post_header, verify=False
            ).json()

            for item in response_layer.get("vulnerabilities", {}):
                affected = item.get("name", {})
                vulnerable_name = item.get("name", {})
                vulnerable_version = item.get("version", {})
                namespace_name = item.get("namespaceName", {})
                for vul in item.get("vulnerabilities", {}):
                    vul_cve = vul.get("name", {})

                    vul_severity = vul.get("severity", {}).lower()
                    if (vul_severity not in cfg["criticalities"]) and (
                        vul_severity != "unknown"
                    ):
                        continue

                    if vul_severity == "defcon1":
                        vul_count_defcon1 += 1
                    if vul_severity == "critical":
                        vul_count_critical += 1
                    if vul_severity == "high":
                        vul_count_high += 1
                    if vul_severity == "medium":
                        vul_count_medium += 1

                    vul_av2 = (
                        vul.get("metadata", {})
                        .get("NVD", {})
                        .get("CVSSv2", {})
                        .get("Vectors", {})
                    )
                    vul_av3 = (
                        vul.get("metadata", {})
                        .get("NVD", {})
                        .get("CVSSv3", {})
                        .get("Vectors", {})
                    )
                    if (str(vul_av2).find("AV:N") >= 0) or (
                        str(vul_av3).find("AV:N") >= 0
                    ):
                        vul_av = "network"
                    else:
                        vul_av = "local"

                    vulns[str(vul_cve)] = {
                        "name": str(vulnerable_name),
                        "version": str(vulnerable_version),
                        "severity": str(vul_severity),
                        "namespace_name": str(namespace_name),
                        "av": str(vul_av),
                        "description": vul.get("description", "n/a"),
                        "link": vul.get("link", "n/a"),
                        "fixed_by": vul.get("fixedBy", "n/a"),
                    }

    scan_info = {
        "id": scan_id,
        "requested": scan_requested_time,
        "database_time": database_time,
        "defcon1": vul_count_defcon1,
        "critical": vul_count_critical,
        "high": vul_count_high,
        "medium": vul_count_medium,
    }

    return {"scan_info": scan_info, "vulns": vulns}


def dssc_report(cfg):
    ###Queries the scan report of the given image from Smart Check###

    token = dssc_auth(cfg)
    scan_id = dssc_latest_scan(cfg, token)
    scan_info = dssc_scan(cfg, scan_id, token)

    return scan_info


def recalc_fontsize(pdf, s, w, fs):
    ###Recalculates the font size if string is to wide###

    string_width = pdf.get_string_width(s)
    scale_factor = w / string_width
    rescaled = fs
    if scale_factor < 1:
        rescaled = fs * scale_factor

    return int(round(rescaled))


def create_vulns_list(pdf, dssc_vulns, av, criticality):
    ###Creates table for vulnerabilities, can be limited to attack vector and criticaliyty###

    # Effective page width, or just epw
    epw = pdf.w - 2 * pdf.l_margin

    # Set column width to 1/3 of effective page width to distribute content
    # evenly across table and page
    col_width = epw / 3

    # Attack Vector: Network, Severity: Critical
    pdf.ln(pdf.font_size * 2.5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(
        160,
        10,
        "Attack Vector: " + av.title() + ", Severity: " + criticality.title(),
        0,
        0,
    )

    # Line break
    pdf.ln(pdf.font_size * 2.5)

    # Create Table
    for vul in {k: dssc_vulns[k] for k in sorted(dssc_vulns)}:
        if (
            dssc_vulns.get(vul, {}).get("av", {}) == av
            and dssc_vulns.get(vul, {}).get("severity", {}) == criticality
        ):

            link_vul = str(dssc_vulns.get(vul, {}).get("link", {}))
            pdf.set_font("Arial", "", recalc_fontsize(pdf, str(vul), col_width * 3, 12))
            pdf.cell(col_width * 3, pdf.font_size * 1.5, txt=str(vul), border=1, link=link_vul)
            pdf.ln(pdf.font_size * 1.5)

            pdf.set_font("Arial", "", 12)
            name = "Name: " + str(dssc_vulns.get(vul, {}).get("name", {}))
            version = "Vers: " + str(dssc_vulns.get(vul, {}).get("version", {}))
            fixed_by = "Fix: " + str(dssc_vulns.get(vul, {}).get("fixed_by", {}))
            # pdf.set_font("Arial", "", recalc_fontsize(pdf, name, col_width, 12))
            # pdf.cell(col_width, pdf.font_size * 1.5, str(name), 1)
            pdf.set_font("Arial", "", recalc_fontsize(pdf, version, col_width, 12))
            pdf.cell(col_width * 1.5, pdf.font_size * 1.5, str(version), 1)
            pdf.set_font("Arial", "", recalc_fontsize(pdf, fixed_by, col_width, 12))
            pdf.cell(col_width * 1.5, pdf.font_size * 1.5, str(fixed_by), 1)
            pdf.ln(pdf.font_size * 1.5)

            description = (
                name
                + "\n"
                + "Namespace: "
                + str(dssc_vulns.get(vul, {}).get("namespace_name", {}))
                + "\n"
                + "Description: "
                + str(dssc_vulns.get(vul, {}).get("description", {}))
            )
            # pdf.set_font('Arial', '', recalc_fontsize(pdf, link, col_width * 3, 12))
            pdf.multi_cell(
                col_width * 3,
                pdf.font_size * 1.5,
                description.encode("latin-1", "replace").decode("latin-1"),
                1,
            )
            pdf.ln(pdf.font_size * 1.5)

            # remove processed vulnerability from dictionary
            dssc_vulns.pop(vul, None)

    return dssc_vulns


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config_path", type=str, help="path to config.yml")
    parser.add_argument("-n", "--name", type=str, help="image name")
    parser.add_argument("-t", "--image_tag", type=str, help="image tag")
    parser.add_argument("-o", "--out_path", type=str, help="output directory")
    parser.add_argument("-s", "--service", type=str, help="image security url")
    parser.add_argument("-u", "--username", type=str, help="username")
    parser.add_argument("-p", "--password", type=str, help="password")
    parser.add_argument("-O", "--stdout", action="store_true", help="output to stdout")
    args = parser.parse_args()

    config_path = "."
    if args.config_path != None:
        config_path = args.config_path

    out_dir = config_path
    if args.out_path != None:
        out_dir = args.out_path

    with open(config_path + "/config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    # Dirty override configuraton with command line parameters
    if args.name != None:
        cfg["repository"]["name"] = args.name
    if args.image_tag != None:
        cfg["repository"]["image_tag"] = args.image_tag
    if args.service != None:
        cfg["dssc"]["service"] = args.service
    if args.username != None:
        cfg["dssc"]["username"] = args.username
    if args.password != None:
        cfg["dssc"]["password"] = args.password

    # Query Report
    results = dssc_report(cfg)
    scan_info = results.get("scan_info", {})
    dssc_vulns = results.get("vulns", {})

    if not args.stdout:
        print("Database time {}".format(scan_info.get("database_time", {})))
        print("Scan requested at {}".format(scan_info.get("requested", {})))
        print("Scan ID {}".format(scan_info.get("id", {})))
    vulnerabilities = "defcon1 - {}, critical - {}, high - {}, medium - {}".format(
        scan_info.get("defcon1", {}),
        scan_info.get("critical", {}),
        scan_info.get("high", {}),
        scan_info.get("medium", {}),
    )

    if not args.stdout:
        print("Vulnerabilities: {}".format(vulnerabilities))

    title = cfg["repository"]["name"] + ":" + str(cfg["repository"]["image_tag"])
    pdf = PDF(
        title,
        config_path + "/smartcheck.png",
        scan_info.get("id", {}),
        scan_info.get("requested", {}),
        scan_info.get("database_time", {}),
        vulnerabilities,
    )
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Arial", "", 12)

    # Attack Vector: Network, Severity: Critical
    dssc_vulns = create_vulns_list(pdf, dssc_vulns, "network", "critical")

    # Attack Vector: Network, Severity: High
    dssc_vulns = create_vulns_list(pdf, dssc_vulns, "network", "high")

    # The Rest
    # Effective page width, or just epw
    epw = pdf.w - 2 * pdf.l_margin

    # Set column width to 1/3 of effective page width to distribute content
    # evenly across table and page
    col_width = epw / 3

    # Text height is the same as current font size
    th = pdf.font_size

    pdf.ln(pdf.font_size * 2.5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(160, 10, "Additional Findings", 0, 0)
    # Line break
    pdf.ln(pdf.font_size * 2.5)
    for vul in {k: dssc_vulns[k] for k in sorted(dssc_vulns)}:
        pdf.set_font("Arial", "", recalc_fontsize(pdf, str(vul), col_width, 12))
        pdf.cell(col_width, th * 1.5, str(vul), 1)
        pdf.set_font("Arial", "", 12)
        pdf.cell(col_width, th * 1.5, "AV: " + dssc_vulns.get(vul, {}).get("av", {}), 1)
        pdf.cell(
            col_width,
            th * 1.5,
            "Severity: " + dssc_vulns.get(vul, {}).get("severity", {}),
            1,
        )
        pdf.ln(th * 1.5)

    filename = out_dir + "/report_" + str(cfg["repository"]["name"]).replace('/', '_') + ".pdf"
    if not args.stdout:
        print("Creating PDF report " + filename)
        pdf.output(filename, "F")
    else:
        # Pipe to stdout
        pdf.output(True)

    if not args.stdout:
        print("Done.")

    exit(0)


if __name__ == "__main__":
    main()
