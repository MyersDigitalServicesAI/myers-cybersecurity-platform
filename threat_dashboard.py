import streamlit as st
import pandas as pd
import plotly.express as px
import logging
import random
from datetime import datetime, timedelta

# --- Hardened Module Imports ---
from security_core import SecurityCore
from utils.database import get_db_connection, return_db_connection

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

def _populate_mock_threat_intelligence(security_core: SecurityCore, num_entries: int = 100):
    """
    Populates the threat_intelligence table with mock data for demonstration.
    This function is moved here to adhere to separation of concerns, as it
    does not belong in the SecurityCore module.
    """
    # This is a simplified version of the function from the original security_core.py
    # In a real application, this would be a separate data seeding script.
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            threat_types = ["Malware", "Phishing", "DDoS", "Ransomware", "Insider Threat"]
            sources = ["ThreatFeedX", "OSINT", "InternalDetection"]
            
            for _ in range(num_entries):
                indicator = f"ip-{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                threat_type = random.choice(threat_types)
                confidence = random.randint(50, 100)
                source = random.choice(sources)
                timestamp = datetime.utcnow() - timedelta(days=random.randint(0, 30))
                
                # Use ON CONFLICT DO NOTHING for idempotency
                cursor.execute(
                    """
                    INSERT INTO threat_intelligence (indicator, threat_type, confidence, source, timestamp, status)
                    VALUES (%s, %s, %s, %s, %s, 'active')
                    ON CONFLICT (indicator) DO NOTHING;
                    """,
                    (indicator, threat_type, confidence, source, timestamp)
                )
            conn.commit()
        logger.info(f"Successfully populated or updated mock threat intelligence data.")
        return True
    except Exception as e:
        logger.error(f"Database error populating mock threat data: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            return_db_connection(conn)

def show_threat_detection_dashboard(security_core: SecurityCore):
    """
    Renders the threat intelligence dashboard.
    This version is hardened with proper database connection handling and a non-blocking UI.
    """
    st.markdown("### 📊 Threat Intelligence Dashboard")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("Generate Mock Threat Data (for Demo)"):
            with st.spinner("Generating mock data..."):
                if _populate_mock_threat_intelligence(security_core, num_entries=200):
                    st.success("Mock threat data generated! Refreshing dashboard...")
                    st.rerun()
                else:
                    st.error("Failed to generate mock data. Check logs.")
    with col2:
        if st.button("🔄 Refresh Data"):
            st.rerun()

    conn = None
    try:
        # --- FIX APPLIED: Proper Database Connection Handling ---
        # A try...finally block ensures the connection is always returned to the pool.
        conn = get_db_connection()
        threat_data = pd.read_sql(
            """
            SELECT timestamp, indicator, threat_type, confidence, source
            FROM threat_intelligence
            WHERE status = 'active'
            ORDER BY timestamp DESC LIMIT 500
            """,
            con=conn
        )
    except Exception as e:
        logger.error(f"Error loading threat data: {e}", exc_info=True)
        st.error(f"Error loading threat data: {e}. Please check database connection.")
        return
    finally:
        if conn:
            return_db_connection(conn)

    if threat_data.empty:
        st.info("No active threat intelligence data found. You can generate some using the button above.")
        return

    # --- Dashboard Metrics and Visualizations ---
    st.markdown("---")
    metric1, metric2 = st.columns(2)
    metric1.metric("Active Threats Logged", value=f"{len(threat_data):,}")
    metric2.metric("Unique Threat Indicators", value=f"{threat_data['indicator'].nunique():,}")
    st.markdown("---")

    st.subheader("Threat Type Distribution")
    type_counts = threat_data['threat_type'].value_counts().reset_index()
    type_counts.columns = ['Threat Type', 'Count']
    fig = px.bar(type_counts, x='Threat Type', y='Count', title='Distribution of Threat Types')
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Raw Threat Data (Last 50 Entries)")
    st.dataframe(threat_data.head(50))

    # --- FIX APPLIED: Removed Blocking Auto-Refresh ---
    # The time.sleep() and st.rerun() have been removed to prevent the UI from freezing.
    # A manual refresh button is the standard and correct pattern for Streamlit dashboards.
