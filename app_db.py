from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from calendar import monthrange
from dateutil.relativedelta import relativedelta
import atexit

app = Flask(__name__)
app.secret_key = "12345678"

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:root@localhost/dashboard"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

def update_ageing():
    with app.app_context():
        try:
            solve_question_2_1_17()
            solve_question_2_1_18()
            solve_question_2_1_22()
            solve_question_2_1_23()
            vuln_entries = VulnTracker.query.all()
            for entry in vuln_entries:
                # update_vulns_table(entry.application_name)
                reported_date = entry.reported_date
                
                if entry.vuln_status != "Closed":
                    ageing = (datetime.now().date() - reported_date).days
                else:
                    if entry.closure_date:
                        ageing = (entry.closure_date - reported_date).days
                    else:
                        ageing = (datetime.now().date() - reported_date).days

                entry.ageing = ageing
                entry.breach_status = "Breached" if ageing > entry.sla else "Not-breached"
            db.session.commit()
            # print(f"Ageing updated successfully at {datetime.now()}")
        except Exception as e:
            print(f"Error updating ageing: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(func=update_ageing, trigger="interval", seconds=5)

# =========================================================================================================

class Inventory(db.Model):
    ria_id = db.Column(db.String(500), primary_key=True, nullable=False)
    application_name = db.Column(db.String(500), unique=True, nullable=False)
    criticality = db.Column(db.String(20), nullable=False)
    public_facing = db.Column(db.String(10), nullable=False)
    cots = db.Column(db.String(10), nullable=False)
    dast = db.Column(db.String(10), nullable=False)

    vulnerabilities = db.relationship('Vulns', backref='inventory', lazy=True)
    vuln_tracker = db.relationship('VulnTracker', backref='inventory', lazy=True)

class Vulns(db.Model):
    ria_id = db.Column(
        db.String(500),
        db.ForeignKey('inventory.ria_id'),
        primary_key=True,
        nullable=False
    )
    total_vulns = db.Column(db.String(500), nullable=False)
    vulns_unresolved = db.Column(db.Integer, nullable=False)
    vulns_unres_excl_low = db.Column(db.Integer, nullable=False)
    last_tested_date = db.Column(db.Date, nullable=True)

class DastVulns(db.Model):
    ria_id = db.Column(
        db.String(500),
        db.ForeignKey('inventory.ria_id'),
        primary_key=True,
        nullable=False
    )
    total_vulns = db.Column(db.String(500), nullable=False)
    vulns_unresolved = db.Column(db.Integer, nullable=False)
    vulns_unres_excl_low = db.Column(db.Integer, nullable=False)
    last_tested_date = db.Column(db.Date, nullable=True)

class VulnTracker(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    application_name = db.Column(
        db.String(500),
        db.ForeignKey('inventory.application_name'),
        nullable=False
    )
    test_type = db.Column(db.String(100), nullable=True)
    vuln_name = db.Column(db.String(500), nullable=False)
    jira_id = db.Column(db.String(100), nullable=True)
    reported_date = db.Column(db.Date, nullable=False)
    ageing = db.Column(db.Integer, nullable=False)
    sla = db.Column(db.Integer, nullable=False)
    breach_status = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(100), nullable=False)
    occurence = db.Column(db.String(500), nullable=True)
    vuln_status = db.Column(db.String(100), nullable=False)
    closure_date = db.Column(db.Date, nullable=True)
    close_remarks = db.Column(db.String(500), nullable=True)

class kri(db.Model):
    question_no = db.Column(db.String(100), primary_key=True, autoincrement=False)
    question = db.Column(db.Text, nullable=False)
    au_remarks = db.Column(db.Text)
    fincare_remarks = db.Column(db.Text)
    au_percent = db.Column(db.Numeric)
    fincare_percent = db.Column(db.Numeric)
    total_percent = db.Column(db.Numeric)
    remarks = db.Column(db.Text)

# =========================================================================================================

def populate_vulns_table():
    application_names = VulnTracker.query.with_entities(VulnTracker.application_name).distinct()

    for app_name in application_names:
        app_name = app_name[0]

        inventory_entry = Inventory.query.filter_by(application_name=app_name).first()
        if not inventory_entry:
            continue

        ria_id = inventory_entry.ria_id

        total_vulns = VulnTracker.query.filter_by(application_name=app_name).count()
        unresolved_vulns = VulnTracker.query.filter(
        VulnTracker.application_name == app_name,
        VulnTracker.vuln_status != "Closed"
        ).count()
        unresolved_excl_low = VulnTracker.query.filter(
            VulnTracker.application_name == app_name,
            VulnTracker.vuln_status != "Closed",
            VulnTracker.severity != "Low"
        ).count()

        critical_count = VulnTracker.query.filter_by(application_name=app_name, severity="Critical").count()
        high_count = VulnTracker.query.filter_by(application_name=app_name, severity="High").count()
        medium_count = VulnTracker.query.filter_by(application_name=app_name, severity="Medium").count()
        low_count = VulnTracker.query.filter_by(application_name=app_name, severity="Low").count()

        total_vulns_str = f"Total: {total_vulns}| C: {critical_count}| H: {high_count}| M: {medium_count}| L: {low_count}"

        vuln_entry = Vulns.query.filter_by(ria_id=ria_id).first()
        if vuln_entry:
            vuln_entry.total_vulns = total_vulns_str
            vuln_entry.vulns_unresolved = unresolved_vulns
            vuln_entry.vulns_unres_excl_low = unresolved_excl_low
        else:
            new_vuln_entry = Vulns(
                ria_id=ria_id,
                total_vulns=total_vulns_str,
                vulns_unresolved=unresolved_vulns,
                vulns_unres_excl_low=unresolved_excl_low,
            )
            db.session.add(new_vuln_entry)

    db.session.commit()

# =========================================================================================================

def update_vulns_table(application_name):
    inventory_entry = Inventory.query.filter_by(application_name=application_name).first()
    if not inventory_entry:
        return

    ria_id = inventory_entry.ria_id

    total_vulns = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
    ).count()
    unresolved_vulns = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.vuln_status != "Closed"
    ).count()
    unresolved_excl_low = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.vuln_status != "Closed",
        VulnTracker.severity != "Low"
    ).count()

    critical_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.severity == "Critical"
    ).count()
    high_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.severity == "High"
    ).count()
    medium_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.severity == "Medium"
    ).count()
    low_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type != "DAST",
        VulnTracker.severity == "Low"
    ).count()

    total_vulns_str = f"Total: {total_vulns}| C: {critical_count}| H: {high_count}| M: {medium_count}| L: {low_count}"

    vuln_entry = Vulns.query.filter_by(ria_id=ria_id).first()
    if vuln_entry:
        vuln_entry.total_vulns = total_vulns_str
        vuln_entry.vulns_unresolved = unresolved_vulns
        vuln_entry.vulns_unres_excl_low = unresolved_excl_low
        vuln_entry.last_tested_date = datetime.now().date()
    else:
        new_vuln_entry = Vulns(
            ria_id=ria_id,
            total_vulns=total_vulns_str,
            vulns_unresolved=unresolved_vulns,
            vulns_unres_excl_low=unresolved_excl_low,
            last_tested_date=datetime.now().date()
        )
        db.session.add(new_vuln_entry)

    db.session.commit()

def update_dast_vulns_table(application_name):
    inventory_entry = Inventory.query.filter_by(application_name=application_name).first()
    if not inventory_entry:
        return

    ria_id = inventory_entry.ria_id

    total_vulns = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
    ).count()
    unresolved_vulns = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.vuln_status != "Closed"
    ).count()
    unresolved_excl_low = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.vuln_status != "Closed",
        VulnTracker.severity != "Low"
    ).count()

    critical_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.severity == "Critical"
    ).count()
    high_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.severity == "High"
    ).count()
    medium_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.severity == "Medium"
    ).count()
    low_count = VulnTracker.query.filter(
        VulnTracker.application_name == application_name,
        VulnTracker.test_type == "DAST",
        VulnTracker.severity == "Low"
    ).count()

    total_vulns_str = f"Total: {total_vulns}| C: {critical_count}| H: {high_count}| M: {medium_count}| L: {low_count}"

    dast_entry = DastVulns.query.filter_by(ria_id=ria_id).first()
    if dast_entry:
        dast_entry.total_vulns = total_vulns_str
        dast_entry.vulns_unresolved = unresolved_vulns
        dast_entry.vulns_unres_excl_low = unresolved_excl_low
        dast_entry.last_tested_date = datetime.now().date()
    else:
        new_dast_entry = DastVulns(
            ria_id=ria_id,
            total_vulns=total_vulns_str,
            vulns_unresolved=unresolved_vulns,
            vulns_unres_excl_low=unresolved_excl_low,
            last_tested_date=datetime.now().date()
        )
        db.session.add(new_dast_entry)

    db.session.commit()

# =========================================================================================================

def get_quarter_and_date_range(current_date=None):
    if not current_date:
        current_date = datetime.now().date()

    current_month = current_date.month
    current_year = current_date.year

    if 1 <= current_month <= 3:
        current_quarter = "Q4"
        start_date = datetime(current_year - 1, 7, 1).date()
        end_date = datetime(current_year - 1, 12, 31).date()
    elif 4 <= current_month <= 6:
        current_quarter = "Q1"
        start_date = datetime(current_year - 1, 10, 1).date()
        end_date = datetime(current_year, 3, 31).date()
    elif 7 <= current_month <= 9:
        current_quarter = "Q2"
        start_date = datetime(current_year, 1, 1).date()
        end_date = datetime(current_year, 6, 30).date()
    else:
        current_quarter = "Q3"
        start_date = datetime(current_year, 4, 1).date()
        end_date = datetime(current_year, 9, 30).date()

    return current_quarter, start_date, end_date

# =========================================================================================================

def solve_question_2_1_17():
    current_quarter, start_date, end_date = get_quarter_and_date_range()

    critical_apps = Inventory.query.filter_by(criticality="Critical").all()
    critical_app_names = [app.application_name for app in critical_apps]

    two_months_ago = end_date - relativedelta(months=2)
    six_months_ago = end_date - relativedelta(months=5)

    last_day_two_months_ago = monthrange(two_months_ago.year, two_months_ago.month)[1]
    two_months_ago = two_months_ago.replace(day=last_day_two_months_ago)

    six_months_ago = six_months_ago.replace(day=1)

    # print("2-6")
    # print(six_months_ago)
    # print(two_months_ago)
    # print(end_date)
    # print("==================")

    numerator = VulnTracker.query.filter(
        VulnTracker.application_name.in_(critical_app_names),
        VulnTracker.vuln_status == "Open",
        VulnTracker.reported_date.between(six_months_ago, two_months_ago)
    ).count()

    denominator = VulnTracker.query.filter(
        VulnTracker.application_name.in_(critical_app_names),
        VulnTracker.reported_date.between(six_months_ago, end_date)
    ).count()

    percentage = ((numerator / denominator) * 100) if denominator > 0 else 0

    question_entry = kri.query.filter_by(question_no="2.1.17").first()
    if question_entry:
        question_entry.au_percent = percentage
        question_entry.remarks = f"Open vulns of critical apps pending 2-6 months: {numerator}. Total vulns of critical apps upto 6 months: {denominator}"
    else:
        new_entry = kri(
            question_no="2.1.17",
            question="Percentage of [Number of open/outstanding findings from security assessments (VA/PT/AppSec) of critical applications pending beyond two months but up to six months to total number of observations from security assessments (VA/PT/AppSec) of critical applications in last six months]",
            au_percent=percentage,
            # remarks=f"{numerator}/{denominator}"
            remarks=f"Open vulns of critical apps pending 2-6 months: {numerator}. Total vulns of critical apps upto 6 months: {denominator}"
        )
        db.session.add(new_entry)
    db.session.commit()

# =========================================================================================================

def solve_question_2_1_18():
    current_quarter, start_date, end_date = get_quarter_and_date_range()

    critical_apps = Inventory.query.filter_by(criticality="Critical").all()
    critical_app_names = [app.application_name for app in critical_apps]

    six_months_ago = end_date - relativedelta(months=6)
    twelve_months_ago = end_date - relativedelta(months=11)

    last_day_six_months_ago = monthrange(six_months_ago.year, six_months_ago.month)[1]
    six_months_ago = six_months_ago.replace(day=last_day_six_months_ago)

    twelve_months_ago = twelve_months_ago.replace(day=1)

    # print("6-12")
    # print(twelve_months_ago)
    # print(six_months_ago)
    # print(end_date)
    # print("============================")

    numerator = VulnTracker.query.filter(
        VulnTracker.application_name.in_(critical_app_names),
        VulnTracker.vuln_status == "Open",
        VulnTracker.reported_date.between(twelve_months_ago, six_months_ago)
    ).count()

    denominator = VulnTracker.query.filter(
        VulnTracker.application_name.in_(critical_app_names),
        VulnTracker.reported_date.between(twelve_months_ago, end_date)
    ).count()

    percentage = ((numerator / denominator) * 100) if denominator > 0 else 0

    question_entry = kri.query.filter_by(question_no="2.1.18").first()
    if question_entry:
        question_entry.au_percent = percentage
        question_entry.remarks = f"Open vulns of critical apps pending 6-12 months: {numerator}. Total vulns of critical apps upto 12 months: {denominator}"
    else:
        new_entry = kri(
            question_no="2.1.18",
            question="Percentage of [Number of open/outstanding findings from security assessments (VA/PT/AppSec) of critical applications pending beyond six months but up to 12 months to total number of observations from security assessments (VA/PT/AppSec) of critical applications in last 12 months]",
            au_percent=percentage,
            remarks=f"Open vulns of critical apps pending 6-12 months: {numerator}. Total vulns of critical apps upto 12 months: {denominator}"
        )
        db.session.add(new_entry)
    db.session.commit()

# =========================================================================================================

def solve_question_2_1_22():
    non_public_apps = Inventory.query.filter_by(public_facing="No").all()

    total_apps_count = 0
    non_compliant_count = 0

    for app in non_public_apps:
        total_apps_count += 1

        vulnerabilities = VulnTracker.query.filter_by(application_name=app.application_name).all()

        open_vulns = [vuln for vuln in vulnerabilities if vuln.vuln_status == "Open"]
        low_severity_vulns = [vuln for vuln in open_vulns if vuln.severity == "Low"]

        if len(open_vulns) > len(low_severity_vulns):
            non_compliant_count += 1

    percentage_non_compliant = (non_compliant_count / total_apps_count * 100) if total_apps_count > 0 else 0

    question_entry = kri.query.filter_by(question_no="2.1.22").first()
    if question_entry:
        question_entry.au_percent = percentage_non_compliant
        question_entry.remarks = f"Non-compliant non-public facing applications: {non_compliant_count}. Total non-public facing applications: {total_apps_count}"
    else:
        new_entry = kri(
            question_no="2.1.22",
            question="Percentage of [web applications not exposed in public domain that are not OWASP Top 10 compliant to total web applications not exposed in public domain in production environment]. For the purpose of this data point, exclude the low risk vulnerabilities.",
            au_percent=percentage_non_compliant,
            remarks=f"Non-compliant non-public facing applications: {non_compliant_count}. Total non-public facing applications: {total_apps_count}"
        )
        db.session.add(new_entry)
    db.session.commit()

# =========================================================================================================

def solve_question_2_1_23():
    public_facing_apps = Inventory.query.filter_by(public_facing="Yes").all()

    total_apps_count = 0
    non_compliant_count = 0

    for app in public_facing_apps:
        total_apps_count += 1

        vulnerabilities = VulnTracker.query.filter_by(application_name=app.application_name).all()

        open_vulns = [vuln for vuln in vulnerabilities if vuln.vuln_status == "Open"]
        low_severity_vulns = [vuln for vuln in open_vulns if vuln.severity == "Low"]

        if len(open_vulns) > len(low_severity_vulns):
            non_compliant_count += 1

    percentage_non_compliant = (non_compliant_count / total_apps_count * 100) if total_apps_count > 0 else 0

    question_entry = kri.query.filter_by(question_no="2.1.23").first()
    if question_entry:
        question_entry.au_percent = percentage_non_compliant
        question_entry.remarks = f"Non-compliant public facing applications: {non_compliant_count}. Total public facing applications: {total_apps_count}"
    else:
        new_entry = kri(
            question_no="2.1.23",
            question="Percentage of [web applications that are exposed in public domain that are not OWASP Top 10 compliant (as assessed by the bank) to total web Applications that are exposed in public domain]. For the purpose of this data point, exclude the low risk vulnerabilities.",
            au_percent=percentage_non_compliant,
            remarks=f"Non-compliant public facing applications: {non_compliant_count}. Total public facing applications: {total_apps_count}"
        )
        db.session.add(new_entry)
    db.session.commit()

# =========================================================================================================

with app.app_context():
    db.create_all()
    update_ageing()
    # populate_vulns_table()

scheduler.start()
atexit.register(lambda: scheduler.shutdown())

@app.route("/", methods=["GET", "POST"])
def dashboard():
    if request.method == "POST":
        try:
            ria_id = request.form["ria_id"]
            application_name = request.form["application_name"]
            criticality = request.form["criticality"]
            public_facing = request.form["public_facing"]
            cots = request.form["cots"]
            dast = request.form["dast"]

            new_inventory = Inventory(
                ria_id=ria_id,
                application_name=application_name,
                criticality=criticality,
                public_facing=public_facing,
                cots=cots,
                dast=dast,
            )
            db.session.add(new_inventory)

            db.session.commit()
            flash("Inventory added successfully!", "success")
        except IntegrityError:
            db.session.rollback()
            flash(f"Error: Entry for '{ria_id}' and/or '{application_name}' already exists.", "danger")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search_query", "")

    if search_query:
        combined_data = db.session.query(
            Inventory.ria_id,
            Inventory.application_name,
            Inventory.criticality,
            Inventory.public_facing,
            Inventory.cots,
            Inventory.dast,
            Vulns.total_vulns,
            Vulns.vulns_unresolved,
            Vulns.vulns_unres_excl_low,
            Vulns.last_tested_date
        ).outerjoin(Vulns, Inventory.ria_id == Vulns.ria_id).filter(
            (Inventory.application_name.like(f"%{search_query}%")) |
            (Inventory.ria_id.like(f"%{search_query}%"))
        )

        dast_data = db.session.query(
            Inventory.ria_id,
            Inventory.application_name,
            Inventory.dast,
            DastVulns.total_vulns,
            DastVulns.vulns_unresolved,
            DastVulns.vulns_unres_excl_low,
            DastVulns.last_tested_date
        ).outerjoin(DastVulns, Inventory.ria_id == DastVulns.ria_id).filter(
            (Inventory.application_name.like(f"%{search_query}%")) |
            (Inventory.ria_id.like(f"%{search_query}%"))
        )

    else:
        combined_data = db.session.query(
            Inventory.ria_id,
            Inventory.application_name,
            Inventory.criticality,
            Inventory.public_facing,
            Inventory.cots,
            Inventory.dast,
            Vulns.total_vulns,
            Vulns.vulns_unresolved,
            Vulns.vulns_unres_excl_low,
            Vulns.last_tested_date
        ).outerjoin(Vulns, Inventory.ria_id == Vulns.ria_id).all()

        dast_data = db.session.query(
            Inventory.ria_id,
            Inventory.application_name,
            Inventory.dast,
            DastVulns.total_vulns,
            DastVulns.vulns_unresolved,
            DastVulns.vulns_unres_excl_low,
            DastVulns.last_tested_date
        ).outerjoin(DastVulns, Inventory.ria_id == DastVulns.ria_id).all()

    return render_template("dashboard.html", combined_data=combined_data, dast_data=dast_data)

# =========================================================================================================

@app.route("/edit/<application_name>", methods=["GET", "POST"])
def edit(application_name):
    inventory = Inventory.query.filter_by(application_name=application_name).first()
    if not inventory:
        flash("Inventory not found!", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        entered_secret_key = request.form.get("secret_key")
        if entered_secret_key != app.secret_key:
            flash("Invalid secret key! Please try again.", "danger")
            return redirect(url_for("edit", application_name=application_name))

        try:
            inventory.criticality = request.form["criticality"]
            inventory.public_facing = request.form["public_facing"]
            inventory.cots = request.form["cots"]

            db.session.commit()
            flash(f"Inventory '{application_name}' updated successfully!", "success")
        except IntegrityError:
            db.session.rollback()
            flash(f"Error: Entry for '{application_name}' already exists.", "danger")
        except Exception:
            db.session.rollback()
            flash("An unexpected error occurred. Please try again later.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", inventory=inventory)

# =========================================================================================================

@app.route("/delete/<application_name>", methods=["GET"])
def delete(application_name):
    inventory = Inventory.query.filter_by(application_name=application_name).first()
    
    if not inventory:
        flash("Inventory not found!", "danger")
        return redirect(url_for("dashboard"))

    try:
        db.session.delete(inventory)
        Vulns.query.filter_by(ria_id=inventory.ria_id).delete()
        db.session.commit()

        flash(f"Inventory '{application_name}' deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting inventory '{application_name}': {str(e)}", "danger")

    return redirect(url_for("dashboard"))

# =========================================================================================================

@app.route("/vuln_tracker", methods=["GET", "POST"])
def vuln_tracker():
    application_names = [app.application_name for app in Inventory.query.all()]
    application_names.sort()

    if request.method == "POST":
        try:
            application_name = request.form["application_name"]
            test_type = request.form["test_type"]
            vuln_name = request.form["vuln_name"]
            jira_id = request.form["jira_id"]
            occurence = request.form["occurence"]
            close_remarks = request.form["close_remarks"]
            reported_date = datetime.strptime(request.form["reported_date"], "%Y-%m-%d")
            severity = request.form["severity"]
            vuln_status = request.form["vuln_status"]
            closure_date = request.form["closure_date"]

            # Check if the application has dast set to YES for DAST test type
            application = Inventory.query.filter_by(application_name=application_name).first()
            if test_type == "DAST" and application.dast != "YES":
                flash("DAST test type is not allowed for this application.", "danger")
                return redirect(url_for("vuln_tracker"))

            if vuln_status == "Closed" and not closure_date:
                flash("Closure date is required for closed statuses", "danger")
                return redirect(url_for("vuln_tracker"))

            sla = {
                "Critical": 15,
                "High": 30,
                "Medium": 60,
                "Low": 90
            }.get(severity, 90)

            if vuln_status == "Closed":
                ageing = (datetime.strptime(closure_date, "%Y-%m-%d").date() - reported_date.date()).days if closure_date else (datetime.now().date() - reported_date.date()).days
            else:
                ageing = (datetime.now().date() - reported_date.date()).days

            breach_status = "Breached" if ageing > sla else "Not-breached"

            new_entry = VulnTracker(
                application_name=application_name,
                test_type=test_type,
                vuln_name=vuln_name,
                jira_id=jira_id,
                reported_date=reported_date,
                ageing=ageing,
                sla=sla,
                breach_status=breach_status,
                severity=severity,
                occurence=occurence,
                vuln_status=vuln_status,
                closure_date=datetime.strptime(closure_date, "%Y-%m-%d") if closure_date else None,
                close_remarks=close_remarks,
            )
            db.session.add(new_entry)
            db.session.commit()

            # Update the appropriate table based on test type
            if test_type == "DAST":
                update_dast_vulns_table(application_name)
            else:
                update_vulns_table(application_name)

            flash("New vulnerability entry added successfully!", "success")
        except IntegrityError:
            db.session.rollback()
            flash(f"Error: Inventory for application '{application_name}' does not exist.", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"An unexpected error occurred: {e}", "danger")
        return redirect(url_for("vuln_tracker"))

    search_query = request.args.get("search_query", "")
    app_name_query = request.args.get("app_name_query", "")
    search_query = request.args.get("search_query", "")
    search_query = request.args.get("search_query", "")
    search_query = request.args.get("search_query", "")
    search_query = request.args.get("search_query", "")

    if search_query:
        vuln_tracker_data = VulnTracker.query.filter(
            (VulnTracker.application_name.like(f"%{search_query}%")) | 
            (VulnTracker.vuln_name.like(f"%{search_query}%"))
        )
    else:
        vuln_tracker_data = VulnTracker.query.all()

    current_date = datetime.now().date()

    return render_template("vuln_tracker.html",
                           vuln_tracker_data=vuln_tracker_data,
                           application_names=application_names,
                           current_date=current_date,
                           timedelta=timedelta)

    # ... (rest of the code remains unchanged)

# =========================================================================================================

@app.route("/kri_display", methods=["GET", "POST"])
def kri_display():
    search_query = request.args.get("search_query", "")

    if search_query:
        kri_entries = kri.query.filter(
            (kri.question_no.like(f"%{search_query}%"))
        )
    else:
        kri_entries = kri.query.all()

    return render_template("kri.html", kri_entries=kri_entries)

# =========================================================================================================

@app.route("/edit_vuln/<int:id>", methods=["GET", "POST"])
def edit_vuln(id):
    vuln = VulnTracker.query.get(id)
    if not vuln:
        flash("Vulnerability entry not found!", "danger")
        return redirect(url_for("vuln_tracker"))

    if request.method == "POST":
        entered_secret_key = request.form.get("secret_key")
        if entered_secret_key != app.secret_key:
            flash("Invalid secret key! Please try again.", "danger")
            return redirect(url_for("edit_vuln", id=id))

        vuln_status = request.form["vuln_status"]
        closure_date = request.form.get("closure_date")
        close_remarks = request.form["close_remarks"]

        if vuln_status == "Closed" and not closure_date:
            flash("Closure date is required when closing a vulnerability.", "danger")
            return redirect(url_for("edit_vuln", id=id))

        try:
            vuln.vuln_status = vuln_status
            vuln.closure_date = datetime.strptime(closure_date, "%Y-%m-%d") if closure_date else None
            vuln.close_remarks = close_remarks

            db.session.commit()
            flash("Vulnerability entry updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
        return redirect(url_for("vuln_tracker"))

    return render_template("edit_vuln.html", vuln=vuln)

# =========================================================================================================

if __name__ == "__main__":
    app.run(debug=True)