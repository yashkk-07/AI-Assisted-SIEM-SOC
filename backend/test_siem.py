import asyncio
from database import engine, Base, SessionLocal
from models import LogModel, AlertModel, IncidentModel
from ingestion.simulator import simulator_instance
from ai.hybrid_analyst import hybrid_analyst_instance
from ai.reporter import report_generator_instance

# Ensure tables exist
Base.metadata.create_all(bind=engine)

async def run_tests():
    print("[1] Testing Attack Simulation Injection...")
    count = await simulator_instance.inject_scenario("brute_force_lateral")
    print(f" -> Injected {count} events for Brute Force & Lateral Movement.")

    db = SessionLocal()
    try:
        log_count = db.query(LogModel).count()
        alert_count = db.query(AlertModel).count()
        incident_count = db.query(IncidentModel).count()
        print(f"[2] Verification: Total Logs={log_count}, Alerts={alert_count}, Incidents={incident_count}")
        assert log_count > 0, "No logs recorded!"
        assert alert_count > 0, "No alerts generated!"

        print("[3] Inspecting Generated Alerts:")
        for a in db.query(AlertModel).all():
            print(f" - [{a.severity}] {a.id}: {a.title} (Duplicates Suppressed: {a.duplicate_count - 1})")

        print("[4] Testing AI Incident Investigation:")
        first_inc = db.query(IncidentModel).first()
        if first_inc:
            ai_res = hybrid_analyst_instance.analyze_incident(db, first_inc)
            print(" -> AI Summary:", ai_res["summary"][:120], "...")
            print(" -> Blast Radius:", ai_res["blast_radius"][:100], "...")
            print(" -> Playbook Steps:", len(ai_res["playbook"]))

            print("[5] Testing Incident Report Generator:")
            md_rep = report_generator_instance.generate_markdown(db, first_inc.id)
            html_rep = report_generator_instance.generate_html(db, first_inc.id)
            print(f" -> Generated Markdown report ({len(md_rep)} chars)")
            print(f" -> Generated HTML report ({len(html_rep)} chars)")

            print("[6] Testing AI SOC Assistant Chat:")
            chat_reply = hybrid_analyst_instance.chat_query(db, "What should be our immediate containment step?", incident_id=first_inc.id)
            print(" -> AI Reply:", chat_reply[:140], "...")

        print("\n ALL SIEM SOC CORE TESTS PASSED SUCCESSFULLY!")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(run_tests())
