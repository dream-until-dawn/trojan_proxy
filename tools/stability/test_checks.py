import copy
import unittest
from checks import CheckFailure, SERVICE_ROLES, completed_pass, validate_containers, validate_vpn


class StabilityChecksTest(unittest.TestCase):
    def test_missing_service_restart_and_wrong_image_are_failures(self):
        images = {role: {'config_digest': role} for role in SERVICE_ROLES.values()}
        containers = [{'Id': name, 'Image': role, 'RestartCount': 0,
                       'Config': {'Labels': {'com.docker.compose.service': name}},
                       'State': {'Running': True, 'StartedAt': 'fixed', 'OOMKilled': False}}
                      for name, role in SERVICE_ROLES.items()]
        baseline = validate_containers(containers, images)
        self.assertEqual(validate_containers(containers, images, baseline), baseline)
        for kind in ['missing', 'restart', 'image', 'OOM']:
            candidate = copy.deepcopy(containers)
            if kind == 'missing': candidate.pop()
            if kind == 'restart': candidate[0]['RestartCount'] = 1
            if kind == 'image': candidate[0]['Image'] = 'wrong'
            if kind == 'OOM': candidate[0]['State']['OOMKilled'] = True
            with self.subTest(kind=kind), self.assertRaises(CheckFailure):
                validate_containers(candidate, images, baseline)

    def test_vpn_success_requires_real_positive_and_negative(self):
        good = {'checks': {'trojan_google_https': {'status_line': 'HTTP/1.1 204 No Content', 'inner_tls_verified': True},
                           'wrong_password': {'rejected': True}}}
        validate_vpn(good)
        for positive, negative in [(False, True), (True, False), (False, False)]:
            candidate = copy.deepcopy(good)
            candidate['checks']['trojan_google_https']['inner_tls_verified'] = positive
            candidate['checks']['wrong_password']['rejected'] = negative
            with self.assertRaises(CheckFailure): validate_vpn(candidate)

    def test_early_exit_failures_or_missing_hourly_checks_cannot_pass(self):
        self.assertTrue(completed_pass(86400, 86400, 0, 25, True))
        for elapsed, failures, deep, done in [(86399, 0, 25, True), (86400, 1, 25, True), (86400, 0, 24, True), (86400, 0, 25, False)]:
            self.assertFalse(completed_pass(86400, elapsed, failures, deep, done))


if __name__ == '__main__': unittest.main()
