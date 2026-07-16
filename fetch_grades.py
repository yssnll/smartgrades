#!/usr/bin/env python3
"""
SmartGrades sync - fetches grades from SmartSchool for all students.
Detects and stores connection errors (wrong password, changed password, wrong DOB).
"""

import os
import sys
import psycopg2
import psycopg2.extras
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if not DATABASE_URL:
    print("ERROR: DATABASE_URL not set")
    sys.exit(1)


def get_conn():
    return psycopg2.connect(DATABASE_URL, sslmode='require')


def check_connection(school, username, password, dob):
    """
    Manually attempts SmartSchool login to detect the specific error.
    Returns {'ok': True} or {'ok': False, 'type': 'password'|'dob'|'network', 'message': '...'}
    """
    base = f"https://{school}.smartschool.be"
    s = requests.Session()
    s.headers["User-Agent"] = "unofficial Smartschool API interface"

    try:
        r = s.get(f"{base}/login", timeout=15)
        soup = BeautifulSoup(r.text, 'html.parser')
        form = soup.select_one('form[name="login_form"]')

        if not form:
            # Maybe already logged in or unexpected page
            if 'login' not in r.url:
                return {'ok': True}
            return {'ok': False, 'type': 'network',
                    'message': 'Impossible de joindre SmartSchool'}

        data = {inp['name']: inp.get('value', '')
                for inp in form.select('input[name]')}
        data.update({'username': username, 'password': password})

        action = form.get('action') or r.url
        if not action.startswith('http'):
            action = base + action

        r2 = s.post(action, data=data, allow_redirects=True, timeout=15)

        # Still at /login → wrong password (or password changed)
        if '/login' in r2.url and '/account-verification' not in r2.url:
            return {'ok': False, 'type': 'password',
                    'message': 'Le mot de passe a été changé sur SmartSchool'}

        # At /account-verification → password OK, check DOB
        if 'account-verification' in r2.url:
            soup2 = BeautifulSoup(r2.text, 'html.parser')
            form2 = soup2.select_one('form[name="account_verification_form"]')

            if form2:
                data2 = {inp['name']: inp.get('value', '')
                         for inp in form2.select('input[name]')}
                data2['security_question_answer'] = dob

                action2 = form2.get('action') or r2.url
                if not action2.startswith('http'):
                    action2 = base + action2

                r3 = s.post(action2, data=data2, allow_redirects=True, timeout=15)

                if 'account-verification' in r3.url:
                    return {'ok': False, 'type': 'dob',
                            'message': 'Date de naissance incorrecte'}

        return {'ok': True}

    except requests.exceptions.ConnectionError:
        return {'ok': False, 'type': 'network',
                'message': f'Impossible de se connecter à {school}.smartschool.be'}
    except requests.exceptions.Timeout:
        return {'ok': False, 'type': 'network',
                'message': 'SmartSchool ne répond pas (délai dépassé)'}
    except Exception as e:
        return {'ok': False, 'type': 'network',
                'message': f'Erreur réseau: {str(e)[:150]}'}


def fetch_grades(school, username, password, dob):
    """Fetch all grades via the smartschool library. Returns list of grade dicts."""
    from smartschool import Smartschool, AppCredentials
    from smartschool._results import Results
    from smartschool._objects import PercentageGraphic, TextGraphic

    creds = AppCredentials(
        username=username,
        password=password,
        main_url=f"{school}.smartschool.be",
        mfa=dob,
    )
    session = Smartschool(creds)
    grades = []

    for result in Results(session):
        g = result.graphic

        if isinstance(g, PercentageGraphic):
            grade_value = float(g.value)
            grade_type = 'percentage'
            grade_display = str(g.description)
            color = g.color.value if hasattr(g.color, 'value') else str(g.color)
        elif isinstance(g, TextGraphic):
            grade_value = None
            grade_type = 'text'
            grade_display = str(g.value)
            color = g.color.value if hasattr(g.color, 'value') else str(g.color)
        else:
            grade_value = None
            grade_type = 'icon'
            grade_display = str(getattr(g, 'value', ''))
            raw_color = getattr(g, 'color', 'steel')
            color = raw_color.value if hasattr(raw_color, 'value') else str(raw_color)

        course = result.courses[0].name if result.courses else 'Inconnu'
        owner = result.gradebook_owner
        teacher = (f"{owner.first_name} {owner.last_name}".strip()
                   if owner else '')
        period = result.period.name if result.period else ''
        eval_date = (result.date.strftime('%Y-%m-%d')
                     if result.date else '')

        grades.append({
            'eval_name': str(result.name),
            'course': course,
            'teacher': teacher,
            'period': period,
            'eval_date': eval_date,
            'grade_value': grade_value,
            'grade_type': grade_type,
            'grade_display': grade_display,
            'color': color,
            'does_count': result.does_count,
        })

    return grades


def sync_student(student, conn):
    """Sync one student. Returns True on success."""
    sid = student['id']
    school = student['school']
    username = student['username']
    password = student['password'] or ''
    dob = student['mfa'] or ''
    name = student['name']

    print(f"  → {name} ({username}@{school})", flush=True)
    cur = conn.cursor()

    # 1. Check SmartSchool connection
    check = check_connection(school, username, password, dob)

    if not check['ok']:
        msg = check['message']
        print(f"    ❌ {msg}", flush=True)
        cur.execute(
            "UPDATE students SET conn_status='error', conn_error=%s, updated_at=NOW() WHERE id=%s",
            (msg, sid)
        )
        conn.commit()
        return False

    # 2. Fetch grades
    try:
        grades = fetch_grades(school, username, password, dob)
        print(f"    ✅ {len(grades)} notes", flush=True)

        cur.execute("DELETE FROM grades WHERE student_id=%s", (sid,))
        for g in grades:
            cur.execute(
                """INSERT INTO grades
                   (student_id, eval_name, course, teacher, period, eval_date,
                    grade_value, grade_type, grade_display, color, does_count, fetched_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
                (sid, g['eval_name'], g['course'], g['teacher'],
                 g['period'], g['eval_date'], g['grade_value'], g['grade_type'],
                 g['grade_display'], g['color'], g['does_count'])
            )

        cur.execute(
            "UPDATE students SET conn_status='ok', conn_error='', updated_at=NOW() WHERE id=%s",
            (sid,)
        )
        conn.commit()
        return True

    except Exception as e:
        msg = f"Erreur lors de la récupération des notes: {str(e)[:200]}"
        print(f"    ❌ {msg}", flush=True)
        cur.execute(
            "UPDATE students SET conn_status='error', conn_error=%s, updated_at=NOW() WHERE id=%s",
            (msg, sid)
        )
        conn.commit()
        return False


def main():
    print(f"🔄 SmartGrades sync — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)

    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Ensure columns exist (idempotent migration)
    cur.execute("""
        ALTER TABLE students
            ADD COLUMN IF NOT EXISTS conn_status text DEFAULT 'ok',
            ADD COLUMN IF NOT EXISTS conn_error  text DEFAULT '';
    """)
    conn.commit()

    cur.execute(
        "SELECT id, name, school, username, password, mfa FROM students WHERE username != ''"
    )
    students = cur.fetchall()
    print(f"📚 {len(students)} élève(s)", flush=True)

    ok = errors = 0
    for student in students:
        if sync_student(student, conn):
            ok += 1
        else:
            errors += 1

    conn.close()
    print(f"\n✅ {ok} OK  ❌ {errors} erreur(s)", flush=True)


if __name__ == '__main__':
    main()
