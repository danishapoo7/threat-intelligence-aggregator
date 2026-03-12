import streamlit as st
import pandas as pd
import json
import plotly.express as px
from scoring.score import calculate_score
from feeds.feed_loader import load_feeds
from parser.ioc_parser import parse_iocs
from normalization.normalize import normalize_iocs
from correlation.correlation_engine import correlate_iocs
from blocklist.blocklist_generator import generate_blocklist
from database.db_manager import create_table, insert_ioc, get_all_iocs

st.set_page_config(page_title="Threat Intelligence Aggregator", layout="wide")

st.title("🛡 Threat Intelligence Aggregator")

create_table()

menu = st.sidebar.selectbox(
    "Navigation",
    ["Dashboard","IOC Database","IOC Search","Threat Map","Reports"]
)

# -----------------------------
# DASHBOARD
# -----------------------------

if menu == "Dashboard":

    st.header("Threat Intelligence Dashboard")

    if "dashboard_data" not in st.session_state:
        st.session_state.dashboard_data = None

    colA, colB = st.columns(2)

    load = colA.button("Load Threat Feeds")
    clear = colB.button("Clear Dashboard")

    if clear:
        st.session_state.dashboard_data = None
        st.success("Dashboard cleared")

    if load:

        data = load_feeds()
        parsed = parse_iocs(data)

        ips = parsed["ips"]
        domains = parsed["domains"]
        urls = parsed["urls"]
        hashes = parsed["hashes"]

        # NORMALIZATION WITH METADATA
        normalized_ips = normalize_iocs(ips,"IP","IPSum","botnet")

        normalized_domains = normalize_iocs(domains,"DOMAIN","OpenPhish","phishing")

        normalized_urls = normalize_iocs(urls,"URL","URLHaus","malware")

        normalized_hashes = normalize_iocs(hashes,"HASH","ThreatFox","malware")
        correlation = correlate_iocs(ips)

        st.session_state.dashboard_data = {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
            "correlation": correlation
        }

        # INSERT INTO DATABASE
        for ioc in normalized_ips:
            insert_ioc(ioc)

        for ioc in normalized_domains:
            insert_ioc(ioc)

        for ioc in normalized_urls:
            insert_ioc(ioc)

        for ioc in normalized_hashes:
            insert_ioc(ioc)

    # DISPLAY DASHBOARD DATA

    if st.session_state.dashboard_data:

        ips = st.session_state.dashboard_data["ips"]
        domains = st.session_state.dashboard_data["domains"]
        urls = st.session_state.dashboard_data["urls"]
        hashes = st.session_state.dashboard_data["hashes"]
        correlation = st.session_state.dashboard_data["correlation"]

        col1,col2,col3,col4 = st.columns(4)

        col1.metric("IPs",len(ips))
        col2.metric("Domains",len(domains))
        col3.metric("URLs",len(urls))
        col4.metric("Hashes",len(hashes))

        chart_data = {
            "IPs":len(ips),
            "Domains":len(domains),
            "URLs":len(urls),
            "Hashes":len(hashes)
        }

        df_chart = pd.DataFrame(list(chart_data.items()),columns=["Type","Count"])

        fig = px.pie(df_chart,names="Type",values="Count",title="IOC Distribution")

        st.plotly_chart(fig, width="stretch")

        st.subheader("Parsed IPs")
        st.dataframe(pd.DataFrame(ips,columns=["IP"]))

        st.subheader("Parsed Domains")
        st.dataframe(pd.DataFrame(domains,columns=["Domain"]))

        st.subheader("Parsed URLs")
        st.dataframe(pd.DataFrame(urls,columns=["URL"]))

        st.subheader("Parsed Hashes")
        st.dataframe(pd.DataFrame(hashes,columns=["Hash"]))

        st.subheader("Correlation Results")

        corr_df = pd.DataFrame(correlation)

        st.dataframe(corr_df)

        generate_blocklist(ips,"ip_blocklist.txt")
        generate_blocklist(domains,"domain_blocklist.txt")
        generate_blocklist(urls,"url_blocklist.txt")

        st.success("Blocklists generated successfully")

    else:
        st.info("Click 'Load Threat Feeds' to populate the dashboard.")

# -----------------------------
# IOC DATABASE
# -----------------------------

elif menu == "IOC Database":

    st.header("IOC Database")

    rows = get_all_iocs()

    if rows:

        df = pd.DataFrame(rows,columns=[
            "ID","Type","Value","Source","Timestamp","Category","Severity"
        ])
        

        ioc_type = st.selectbox(
            "Filter IOC Type",
            ["ALL","IP","DOMAIN","URL","HASH"]
        )

        if ioc_type != "ALL":
            df = df[df["Type"] == ioc_type]

        st.dataframe(df)

    else:
        st.info("Database is empty")

# -----------------------------
# IOC SEARCH
# -----------------------------

elif menu == "IOC Search":

    st.header("Search Indicators of Compromise")

    search = st.text_input("Search IOC")

    rows = get_all_iocs()

    if search:

        results = [r for r in rows if search.lower() in r[2].lower()]

        if results:
            df = pd.DataFrame(results,columns=[
                "ID","Type","Value","Source","Timestamp","Category","Severity"
            ])
            st.dataframe(df)
        else:
            st.warning("No IOC found")

# -----------------------------
# THREAT MAP
# -----------------------------

elif menu == "Threat Map":

    st.header("Global Threat Map")

    map_data = pd.DataFrame({
        "lat":[37.77,51.50,28.61,35.68],
        "lon":[-122.41,-0.12,77.20,139.69]
    })

    st.map(map_data)

# -----------------------------
# REPORTS
# -----------------------------

elif menu == "Reports":

    st.header("Threat Intelligence Report")

    rows = get_all_iocs()

    if rows:

        df = pd.DataFrame(rows,columns=[
            "ID","Type","Value","Source","Timestamp","Category","Severity"
        ])
        # Calculate score
        scores = []

        for _, row in df.iterrows():
           score, _ = calculate_score(1, row["Type"].lower())
           scores.append(score)

        df["RiskScore"] = scores

        st.dataframe(df)
        st.subheader("Top Risk Indicators")

        top_risk = df.sort_values("RiskScore", ascending=False).head(10)

        st.dataframe(top_risk)
        
        import plotly.express as px

        fig = px.bar(
           top_risk,
           x="Value",
           y="RiskScore",
           color="Severity",
           title="Top Risk Indicators"
       )

        st.plotly_chart(fig, width="stretch")

        total = len(df)

        high = len(df[df["Severity"]=="HIGH"])
        medium = len(df[df["Severity"]=="MEDIUM"])
        low = len(df[df["Severity"]=="LOW"])

        col1,col2,col3,col4 = st.columns(4)

        col1.metric("Total Indicators",total)
        col2.metric("High Risk",high)
        col3.metric("Medium Risk",medium)
        col4.metric("Low Risk",low)

        csv = df.to_csv(index=False)

        st.download_button(
            "Download CSV Report",
            csv,
            "threat_report.csv",
            "text/csv"
        )

        json_data = json.dumps(df.to_dict(orient="records"))

        st.download_button(
            "Download JSON Report",
            json_data,
            "threat_report.json",
            "application/json"
        )

    else:
        st.info("No report data available")