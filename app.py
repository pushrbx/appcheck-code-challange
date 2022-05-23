import json
import os
import pandas as pd
import numpy as np
from cvss import CVSS2
from dateutil.parser import parse
from flask import Flask, render_template, request
from typing import Union


app = Flask(__name__)
data: dict = {}
data_df: Union[pd.DataFrame, None] = None


def get_severity_counts(vulnerability_data: dict) -> dict:
    if len(vulnerability_data) == 0:
        return {}

    severity_counts = {"None": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for item in vulnerability_data["items"]:
        if "cvss_vector" not in item:
            continue
        c = CVSS2(item["cvss_vector"])
        severities = c.severities()
        for severity in severities:
            severity_counts[severity] += 1

    return severity_counts


def get_widget_one_chart_data(vulnerability_data_df: pd.DataFrame) -> list:
    if len(vulnerability_data_df) == 0:
        return []

    result = []
    df = vulnerability_data_df.sort_values(by="last_detected_at")
    davg = df.resample("D", on="last_detected_at")
    davg_df = davg.agg(np.mean)

    for index in davg_df.cvss_score.index:
        result.append([int(index.timestamp()) * 1000, davg_df.cvss_score[index]])

    return result


def get_widget_two_chart_data(vulnerability_data: dict) -> list:
    if len(vulnerability_data) == 0:
        return []

    severity_counts = get_severity_counts(vulnerability_data)
    result = []
    for k in severity_counts.keys():
        result.append([k, severity_counts[k]])

    return result


def get_widget_three_chart_data(vulnerability_data_df: pd.DataFrame) -> list:
    global data_df
    if len(vulnerability_data_df) == 0:
        return []

    result = []
    priority_counts = data_df["priority"].value_counts()

    for priority_counts_index in priority_counts.index:
        result.append(
            [str(priority_counts_index), int(priority_counts[priority_counts_index])]
        )

    return result


@app.route("/")
def dashboard():
    global data
    global data_df
    severity_counts = get_severity_counts(data)

    widget_data = [
        json.dumps(get_widget_one_chart_data(data_df)),
        json.dumps(get_widget_two_chart_data(data)),
        json.dumps(get_widget_three_chart_data(data_df)),
    ]

    return render_template(
        "dashboard.html", severity_counts=severity_counts, widget_data=widget_data
    )


@app.route("/vulnerabilities")
def vulnerabilities():
    global data
    global data_df

    table_data = []
    filters = {
        "category": request.args.get("category"),
        "impact": request.args.get("impact"),
    }

    # reset filters to None if they are empty
    if filters["category"] == "":
        filters["category"] = None

    if filters["impact"] == "":
        filters["impact"] = None

    # let's filter and sort with pandas
    haystack_df = data_df
    if filters["category"] is not None:
        haystack_df = haystack_df[haystack_df["category"] == filters["category"]]

    if filters["impact"] is not None:
        haystack_df = haystack_df[haystack_df["impact"] == filters["impact"]]

    # sorting by impact by default
    sort_by = request.args.get("sort_by", "impact")
    if sort_by.replace("-", "") in [
        "title",
        "impact",
        "category",
        "type",
        "host",
        "created",
    ]:
        ascending = True
        if "-" in sort_by:
            ascending = False
        haystack_df = haystack_df.sort_values(
            by=sort_by.replace("-", ""), ascending=ascending
        )

    for index, row in haystack_df.iterrows():
        item = dict(row.to_dict())
        item["created"] = parse(item["created"])
        table_data.append(item)

    return render_template(
        "vulnerabilities.html",
        table_data=table_data,
        category_filter_options=data_df.category.unique(),
        impact_filter_options=data_df.impact.unique(),
        filters=filters,
        sorting_by=sort_by,
    )


@app.before_first_request
def load_data():
    global data
    global data_df
    if os.path.exists("static/vulnerability_data.json"):
        with open("static/vulnerability_data.json", mode="r") as fp:
            data.update(json.load(fp))
            data_df = pd.read_json(json.dumps(data["items"]))


if __name__ == "__main__":
    app.run()
