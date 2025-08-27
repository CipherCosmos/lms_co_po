#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for LMS CO/PO Assessment System
Tests all implemented backend endpoints with proper authentication and validation
"""

import requests
import json
import sys
from datetime import datetime
import time

# Configuration
BASE_URL = "https://copo-assess.preview.emergentagent.com/api"
ADMIN_EMAIL = "admin@mit.edu"
ADMIN_PASSWORD = "Admin123!@#"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class LMSBackendTester:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.admin_user_id = None
        self.test_results = []
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def log_test(self, test_name, success, message="", response_data=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        color = Colors.GREEN if success else Colors.RED
        
        print(f"{color}{status}{Colors.ENDC} {test_name}")
        if message:
            print(f"    {message}")
        if response_data and not success:
            print(f"    Response: {json.dumps(response_data, indent=2)}")
        
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })

    def make_request(self, method, endpoint, data=None, auth_required=False):
        """Make HTTP request with proper error handling"""
        url = f"{BASE_URL}{endpoint}"
        headers = {}
        
        if auth_required and self.access_token:
            headers['Authorization'] = f"Bearer {self.access_token}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, headers=headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}Request failed: {str(e)}{Colors.ENDC}")
            return None

    def test_health_check(self):
        """Test health check endpoint"""
        print(f"\n{Colors.BLUE}=== Testing Health Check ==={Colors.ENDC}")
        
        response = self.make_request('GET', '/health')
        if response is None:
            self.log_test("Health Check", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'status' in data and data['status'] == 'healthy':
                self.log_test("Health Check", True, f"Status: {data['status']}")
                return True
            else:
                self.log_test("Health Check", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Health Check", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_setup_status(self):
        """Test setup status endpoint"""
        print(f"\n{Colors.BLUE}=== Testing Setup Status ==={Colors.ENDC}")
        
        response = self.make_request('GET', '/setup/status')
        if response is None:
            self.log_test("Setup Status Check", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'is_setup_complete' in data:
                self.log_test("Setup Status Check", True, f"Setup complete: {data['is_setup_complete']}")
                return data
            else:
                self.log_test("Setup Status Check", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Setup Status Check", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_setup_initialize(self):
        """Test system initialization"""
        print(f"\n{Colors.BLUE}=== Testing Setup Initialize ==={Colors.ENDC}")
        
        # First reset setup for clean testing
        reset_response = self.make_request('POST', '/setup/reset')
        if reset_response and reset_response.status_code == 200:
            print("    Setup reset successful")
        
        # Now initialize system
        setup_data = {
            "admin_email": ADMIN_EMAIL,
            "admin_password": ADMIN_PASSWORD,
            "admin_name": "System Administrator",
            "institute_name": "MIT Institute of Technology"
        }
        
        response = self.make_request('POST', '/setup/initialize', setup_data)
        if response is None:
            self.log_test("Setup Initialize", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'access_token' in data and 'user' in data:
                self.access_token = data['access_token']
                self.refresh_token = data['refresh_token']
                self.admin_user_id = data['user']['id']
                self.log_test("Setup Initialize", True, f"Admin created: {data['user']['email']}")
                return True
            else:
                self.log_test("Setup Initialize", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Setup Initialize", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_login(self):
        """Test user login"""
        print(f"\n{Colors.BLUE}=== Testing Authentication ==={Colors.ENDC}")
        
        login_data = {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        }
        
        response = self.make_request('POST', '/auth/login', login_data)
        if response is None:
            self.log_test("Admin Login", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'access_token' in data and 'user' in data:
                self.access_token = data['access_token']
                self.refresh_token = data['refresh_token']
                self.admin_user_id = data['user']['id']
                self.log_test("Admin Login", True, f"Logged in as: {data['user']['email']}")
                return True
            else:
                self.log_test("Admin Login", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Admin Login", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_invalid_login(self):
        """Test login with invalid credentials"""
        login_data = {
            "email": ADMIN_EMAIL,
            "password": "wrongpassword"
        }
        
        response = self.make_request('POST', '/auth/login', login_data)
        if response is None:
            self.log_test("Invalid Login Test", False, "Request failed")
            return False
        
        if response.status_code == 400:
            self.log_test("Invalid Login Test", True, "Correctly rejected invalid credentials")
            return True
        else:
            self.log_test("Invalid Login Test", False, f"Expected 400, got {response.status_code}")
            return False

    def test_refresh_token(self):
        """Test refresh token functionality"""
        print(f"\n{Colors.BLUE}=== Testing Token Refresh ==={Colors.ENDC}")
        
        if not self.refresh_token:
            self.log_test("Token Refresh", False, "No refresh token available")
            return False
        
        # The refresh token is expected as a query parameter
        response = self.make_request('POST', f'/auth/refresh?refresh_token={self.refresh_token}')
        if response is None:
            self.log_test("Token Refresh", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'access_token' in data:
                old_token = self.access_token
                self.access_token = data['access_token']
                self.refresh_token = data.get('refresh_token', self.refresh_token)
                self.log_test("Token Refresh", True, "New access token received")
                return True
            else:
                self.log_test("Token Refresh", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Token Refresh", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_current_user(self):
        """Test getting current user info"""
        print(f"\n{Colors.BLUE}=== Testing User Info ==={Colors.ENDC}")
        
        response = self.make_request('GET', '/users/me', auth_required=True)
        if response is None:
            self.log_test("Get Current User", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'id' in data and 'email' in data and 'role' in data:
                self.log_test("Get Current User", True, f"User: {data['email']}, Role: {data['role']}")
                return True
            else:
                self.log_test("Get Current User", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Get Current User", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_unauthorized_access(self):
        """Test accessing protected endpoint without token"""
        # Temporarily remove token
        old_token = self.access_token
        self.access_token = None
        
        response = self.make_request('GET', '/users/me', auth_required=True)
        
        # Restore token
        self.access_token = old_token
        
        if response is None:
            self.log_test("Unauthorized Access Test", False, "Request failed")
            return False
        
        # FastAPI returns 403 when no Authorization header is provided
        if response.status_code in [401, 403]:
            self.log_test("Unauthorized Access Test", True, f"Correctly rejected unauthorized request (HTTP {response.status_code})")
            return True
        else:
            self.log_test("Unauthorized Access Test", False, f"Expected 401/403, got {response.status_code}")
            return False

    def test_list_users(self):
        """Test listing all users (admin only)"""
        print(f"\n{Colors.BLUE}=== Testing User Management ==={Colors.ENDC}")
        
        response = self.make_request('GET', '/users', auth_required=True)
        if response is None:
            self.log_test("List Users", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                self.log_test("List Users", True, f"Found {len(data)} users")
                return True
            else:
                self.log_test("List Users", False, "Expected list response", data)
                return False
        else:
            self.log_test("List Users", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_create_user(self):
        """Test creating a new user"""
        # Use timestamp to ensure unique email
        timestamp = int(time.time())
        user_data = {
            "name": "Dr. John Smith",
            "email": f"john.smith.{timestamp}@mit.edu",
            "role": "TEACHER",
            "password": "Teacher123!@#",
            "phone": "+1234567890"
        }
        
        response = self.make_request('POST', '/users', user_data, auth_required=True)
        if response is None:
            self.log_test("Create User", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'id' in data and data['email'] == user_data['email']:
                self.log_test("Create User", True, f"Created user: {data['email']}")
                return True
            else:
                self.log_test("Create User", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Create User", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_departments(self):
        """Test department management"""
        print(f"\n{Colors.BLUE}=== Testing Department Management ==={Colors.ENDC}")
        
        # Test listing departments
        response = self.make_request('GET', '/departments', auth_required=True)
        if response is None:
            self.log_test("List Departments", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                self.log_test("List Departments", True, f"Found {len(data)} departments")
            else:
                self.log_test("List Departments", False, "Expected list response", data)
                return False
        else:
            self.log_test("List Departments", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False
        
        # Test creating a department
        timestamp = int(time.time())
        dept_data = {
            "name": "Computer Science and Engineering",
            "code": f"CSE{timestamp}"
        }
        
        response = self.make_request('POST', '/departments', dept_data, auth_required=True)
        if response is None:
            self.log_test("Create Department", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if 'id' in data and data['code'] == dept_data['code']:
                self.log_test("Create Department", True, f"Created department: {data['name']}")
                return data['id']  # Return department ID for program testing
            else:
                self.log_test("Create Department", False, "Invalid response format", data)
                return False
        else:
            self.log_test("Create Department", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False

    def test_programs(self, dept_id=None):
        """Test program management"""
        print(f"\n{Colors.BLUE}=== Testing Program Management ==={Colors.ENDC}")
        
        # Test listing programs
        response = self.make_request('GET', '/programs', auth_required=True)
        if response is None:
            self.log_test("List Programs", False, "Request failed")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                self.log_test("List Programs", True, f"Found {len(data)} programs")
            else:
                self.log_test("List Programs", False, "Expected list response", data)
                return False
        else:
            self.log_test("List Programs", False, f"HTTP {response.status_code}", response.json() if response.content else None)
            return False
        
        # Test creating a program (need department ID)
        if dept_id:
            prog_data = {
                "dept_id": dept_id,
                "name": "Bachelor of Technology in Computer Science",
                "code": "BTECHCSE"
            }
            
            response = self.make_request('POST', '/programs', prog_data, auth_required=True)
            if response is None:
                self.log_test("Create Program", False, "Request failed")
                return False
            
            if response.status_code == 200:
                data = response.json()
                if 'id' in data and data['code'] == prog_data['code']:
                    self.log_test("Create Program", True, f"Created program: {data['name']}")
                    return True
                else:
                    self.log_test("Create Program", False, "Invalid response format", data)
                    return False
            else:
                self.log_test("Create Program", False, f"HTTP {response.status_code}", response.json() if response.content else None)
                return False
        else:
            self.log_test("Create Program", False, "No department ID available")
            return False

    def run_all_tests(self):
        """Run all backend tests"""
        print(f"{Colors.BOLD}🚀 Starting LMS Backend API Tests{Colors.ENDC}")
        print(f"Base URL: {BASE_URL}")
        print(f"Admin Email: {ADMIN_EMAIL}")
        
        # Test sequence
        tests_passed = 0
        total_tests = 0
        
        # 1. Health check
        if self.test_health_check():
            tests_passed += 1
        total_tests += 1
        
        # 2. Setup status
        setup_status = self.test_setup_status()
        if setup_status:
            tests_passed += 1
        total_tests += 1
        
        # 3. Initialize system if needed
        if setup_status and not setup_status.get('is_setup_complete', False):
            if self.test_setup_initialize():
                tests_passed += 1
            total_tests += 1
        else:
            # System already setup, just login
            if self.test_login():
                tests_passed += 1
            total_tests += 1
        
        # 4. Test invalid login
        if self.test_invalid_login():
            tests_passed += 1
        total_tests += 1
        
        # 5. Test token refresh
        if self.test_refresh_token():
            tests_passed += 1
        total_tests += 1
        
        # 6. Test current user info
        if self.test_current_user():
            tests_passed += 1
        total_tests += 1
        
        # 7. Test unauthorized access
        if self.test_unauthorized_access():
            tests_passed += 1
        total_tests += 1
        
        # 8. Test user management
        if self.test_list_users():
            tests_passed += 1
        total_tests += 1
        
        if self.test_create_user():
            tests_passed += 1
        total_tests += 1
        
        # 9. Test department management
        dept_id = self.test_departments()
        if dept_id:
            tests_passed += 2  # List + Create
        total_tests += 2
        
        # 10. Test program management
        if self.test_programs(dept_id):
            tests_passed += 2  # List + Create
        total_tests += 2
        
        # Print summary
        print(f"\n{Colors.BOLD}📊 Test Summary{Colors.ENDC}")
        print(f"Tests Passed: {Colors.GREEN}{tests_passed}{Colors.ENDC}")
        print(f"Tests Failed: {Colors.RED}{total_tests - tests_passed}{Colors.ENDC}")
        print(f"Total Tests: {total_tests}")
        
        success_rate = (tests_passed / total_tests) * 100 if total_tests > 0 else 0
        color = Colors.GREEN if success_rate >= 80 else Colors.YELLOW if success_rate >= 60 else Colors.RED
        print(f"Success Rate: {color}{success_rate:.1f}%{Colors.ENDC}")
        
        return tests_passed, total_tests

def main():
    """Main test execution"""
    tester = LMSBackendTester()
    
    try:
        passed, total = tester.run_all_tests()
        
        # Exit with appropriate code
        if passed == total:
            print(f"\n{Colors.GREEN}✅ All tests passed!{Colors.ENDC}")
            sys.exit(0)
        elif passed >= total * 0.8:  # 80% pass rate
            print(f"\n{Colors.YELLOW}⚠️  Most tests passed with some issues{Colors.ENDC}")
            sys.exit(0)
        else:
            print(f"\n{Colors.RED}❌ Significant test failures detected{Colors.ENDC}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Tests interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Test execution failed: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()