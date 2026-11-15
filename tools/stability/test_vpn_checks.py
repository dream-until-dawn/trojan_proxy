import copy,unittest
from checks import CheckFailure,validate_vpn
from vpn_checks import private_listener_records
class PrivateVPNTests(unittest.TestCase):
    def test_kernel_listener_positive_and_negative(self):
        good={'tcp':'header\n0: 0100007F:480B 00000000:0000 0A\n','tcp6':'header\n'}
        self.assertEqual(private_listener_records(18443,good),{'port':18443,'addresses':['127.0.0.1']})
        for address,family in [('00000000','tcp'),('00000000000000000000000000000000','tcp6'),('00000000000000000000000001000000','tcp6')]:
            bad=copy.deepcopy(good);bad[family]+='1: '+address+':480B 0000:0000 0A\n'
            with self.assertRaisesRegex(CheckFailure,'private_vpn_listener_not_loopback_only'):private_listener_records(18443,bad)
        with self.assertRaises(CheckFailure):private_listener_records(18443,{'tcp':'header\n'})
    def test_deep_probe_cannot_substitute_private_backend(self):
        result={'port':443,'checks':{'trojan_google_https':{'status_line':'HTTP/1.1 204 No Content','inner_tls_verified':True},'wrong_password':{'rejected':True}}}
        validate_vpn(result,443)
        for port in (18443,None,True,'443'):
            result['port']=port
            with self.assertRaisesRegex(CheckFailure,'vpn_public_port_not_tested'):validate_vpn(result,443)
if __name__=='__main__':unittest.main()
