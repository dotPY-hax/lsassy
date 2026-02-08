from lsassy.exec import IExec



class Exec(IExec):
    """
    Remote execution using service creation as SYSTEM

    This execution method provides debug privilege
    """

    debug_privilege = False

    def clean(self):
        # no cleanup needed after code execution
        pass

    def exec(self, command):
        result, result_object, success = self.session.smb_session.execute_ps(command)
        #TODO: better determine success
        return True
