from locust import HttpUser, task, between

HOST = "http://localhost:8000"  # adapte à ton backend


class BaseJWTUser(HttpUser):
    """
    User de base avec login JWT sur /api/auth/login/
    """
    wait_time = between(1, 3)
    host = HOST
    token = None
    headers = {}

    def on_start(self):
        self.login()

    def login(self):
        payload = {
            "username": self.username,
            "password": self.password,
        }
        resp = self.client.post(
            "/api/auth/login/",
            json=payload,
            name="POST /api/auth/login/ [Login]"
        )

        if resp.status_code == 200:
            data = resp.json()
            access = data.get("access")
            if access:
                self.token = access
                self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.token = None
            self.headers = {}


class AdminUser(BaseJWTUser):
    """
    Admin : dashboard, analytics, gestion des ThreatReport
    """
    username = "admin"
    password = "admin_password"

    @task(2)
    def admin_dashboard(self):
        self.client.get(
            "/api/admin/dashboard/",
            headers=self.headers,
            name="GET /api/admin/dashboard/"
        )

    @task(1)
    def admin_aws_status(self):
        self.client.get(
            "/api/admin/aws-status/",
            headers=self.headers,
            name="GET /api/admin/aws-status/"
        )

    @task(1)
    def admin_threat_analytics(self):
        self.client.get(
            "/api/admin/threat-analytics/?days=30",
            headers=self.headers,
            name="GET /api/admin/threat-analytics/"
        )

    @task(1)
    def admin_threat_analytics_detail(self):
        self.client.get(
            "/api/admin/threat-analytics-detail/?days=30",
            headers=self.headers,
            name="GET /api/admin/threat-analytics-detail/"
        )

    @task(2)
    def admin_list_assigned_reports(self):
        """
        Test du ViewSet AdminThreatReportViewSet (list des rapports assignés)
        """
        self.client.get(
            "/api/admin/reports/",          # adapte au routeur DRF: ex. /api/admin/reports/
            headers=self.headers,
            name="GET /api/admin/reports/ [AdminReports]"
        )

    @task(1)
    def admin_filter_reports_critical(self):
        """
        Test filtre ?severity=critical sur AdminThreatReportViewSet
        """
        self.client.get(
            "/api/admin/reports/?severity=critical",
            headers=self.headers,
            name="GET /api/admin/reports/?severity=critical"
        )


class AnalystUser(BaseJWTUser):
    """
    Analyste : analyse + ses ThreatReport
    """
    username = "analyst"
    password = "analyst_password"

    @task(3)
    def analyze_url(self):
        payload = {
            "input_value": "http://example.com/malware",
            "engine_choice": "vt"
        }
        self.client.post(
            "/api/analyst/analyze/",
            json=payload,
            headers=self.headers,
            name="POST /api/analyst/analyze/ [URL]"
        )

    @task(2)
    def analyst_list_own_reports(self):
        """
        Test ThreatReportViewSet côté analyste (list des rapports de l’analyste)
        """
        self.client.get(
            "/api/analyst/reports/",
            headers=self.headers,
            name="GET /api/analyst/reports/ [AnalystReports]"
        )

    @task(1)
    def analyst_list_notifications(self):
        """
        Test NotificationViewSet (notifications non lues)
        """
        self.client.get(
            "/api/notifications/",
            headers=self.headers,
            name="GET /api/notifications/"
        )


class PublicUser(HttpUser):
    """
    Utilisateur public (pas de JWT)
    """
    wait_time = between(1, 3)
    host = HOST

    @task
    def homepage(self):
        self.client.get("/", name="GET / [Homepage]")
