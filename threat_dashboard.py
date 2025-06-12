# thret_detection_dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import time
import logging

from utils.database import get_db_connection # Import the new database utility

logger = logging.getLogger(__name__)

def show_threat_detection_dashboard(security_core):
    st.markdown("### 📊 Threat Intelligence Dashboard")

    if st.button("Generate Mock Threat Data (for Demo)"):
        try:
            security_core.populate_mock_threat_intelligence(num_entries=200)
            st.success("Mock threat data generated! Refreshing dashboard...")
            st.rerun()
        except Exception as e:
            st.error(f"Failed to generate mock data: {e}")

    try:
        conn = get_db_connection() # Use the utility function
        threat_data = pd.read_sql(
            """
            SELECT timestamp, indicator, threat_type, confidence, source
            FROM threat_intelligence
            WHERE status = 'active'
            ORDER BY timestamp DESC LIMIT 500
            """,
            con=conn
        )
        conn.close()

        if threat_data.empty:
            st.info("No active threat intelligence data found. Generate some mock data or integrate a real threat feed.")
            return

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Active Threats", value=len(threat_data))
        with col2:
            st.metric("Unique Indicators", value=threat_data['indicator'].nunique())

        st.markdown("---")
        
        st.subheader("Threat Type Distribution")
        fig = px.histogram(threat_data, x='threat_type', title='Threats by Type', color='threat_type')
        fig.update_layout(xaxis_title="Threat Type", yaxis_title="Count")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Threat Confidence Over Time")
        line_fig = px.line(
            threat_data.sort_values("timestamp"),
            x="timestamp", y="confidence",
            color="threat_type",
            title="Threat Confidence Over Time"
        )
        line_fig.update_layout(xaxis_title="Time", yaxis_title="Confidence Score")
        st.plotly_chart(line_fig, use_container_width=True)

        st.markdown("---")
        st.subheader("Raw Threat Data (Last 50 Entries)")
        st.dataframe(threat_data.head(50))

        st.markdown("---")
        col_export, col_refresh = st.columns([3, 1])
        with col_export:
            csv = threat_data.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="⬇️ Export Threat Data to CSV",
                data=csv,
                file_name='threat_intelligence.csv',
                mime='text/csv'
            )
        with col_refresh:
            if st.button("🔄 Refresh Data"):
                st.rerun()

        st.caption("⏱️ This dashboard auto-refreshes every 60 seconds to fetch the latest data.")
        time.sleep(60)
        st.rerun()

    except Exception as e:
        logger.error(f"Error loading threat data: {e}", exc_info=True)
        st.error(f"Error loading threat data: {e}")
        st.warning("Please ensure your PostgreSQL database is running and the `threat_intelligence` table is correctly set up.")
