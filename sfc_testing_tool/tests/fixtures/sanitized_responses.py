"""Result-element texts captured from the real service, with identities replaced.

Wire format: p_ret char immediately followed by p_msg (+ optional trailer).
"""
LOGIN_OK = "1Welcome using Pegatron SFIS:XXXX(LAST,FIRST)LAST,FIRSTOP"
LOGIN_TWICE = "0Login Twice! SN:10 (D_LOGIN)(TSP_LOGIN)"
RESULT_OK = "1SFIS:ISN OK!!(U)(SM) TEST DATA:SAVED! STATUS:[1] (TSP_TRESULT)310010"
RESULT_BAD_ISN = "0EC1:[0]WRONG ISN:[0]LENGTH !(CHK_ISN)?[M1](SM)(TSP_TRESULT)310010"
# From the protocol documentation (not yet captured from the live service):
LOGIN_USER_NOT_FOUND = "0USER NOT FOUND!(TSP_LOGIN)"
LOGIN_DEVICE_UNDEFINED = "0DEVICE NOT DEFINED!(TSP_LOGIN)"
LOGOUT_OK = "1THANK YOU USING PEGATRON SFIS!(LO)"
CHECK_IN_USE = "1DEV:[123456]IN USED!OP:[P1234] ON:[2006/01/01 08:00:05] (TSP_LOGIN)"
CHECK_FREE = "1DEV:[123456] NOT BEEN USED! (TSP_LOGIN)"
RESULT_WRONG_STEP = "0SFIS DOC..31 WRONG STEP: SFIS test route ROUTE error(TSP_TRESULT)310010"
