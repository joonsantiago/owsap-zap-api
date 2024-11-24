import time
import json
import os
import uvicorn
import logging

from pprint import pprint
from zapv2 import ZAPv2
from datetime import datetime
from dotenv import load_dotenv
from utils import utils;
from urllib.parse import urlparse

load_dotenv()

logger = logging.getLogger('uvicorn.error')

class ZaProxy():

    def __init__(self) -> None:
        self.start_time = time.time()

    def start_scan_target(target: str, context_name: str) -> any:
        """
        Start run scan in the target URL
        
        Args:
            target (str): The URL site to scan DAST
            context_name (str): The context to vincule the target URL

        This function begin and return the ID os scan DAST
        """

        response = utils.Response()

        OWASP_API_KEY: str = os.getenv('OWASP_API_KEY') if os.getenv('OWASP_API_KEY') else None

        try:
            apikey = OWASP_API_KEY
            curr_time = datetime.now()
            formatted_time = curr_time.strftime('%H%M%S')


            if not utils.isValidStr(apikey):
                response.success = False
                response.message = "Invalid configurations, contact suporte [#001]"
                return response
            
            if not utils.isValidStr(target):
                response.success = False
                response.message = "Invalid target value, send valid URL [#002]"
                return response
            
            if not utils.isValidStr(context_name):
                response.success = False
                response.message = "Invalid context value, send valid string [#003]"
                return response

            context = context_name if utils.isValidStr(context_name) else formatted_time
            
            # By default ZAP API client will connect to port 8080
            zap = ZAPv2(apikey=apikey)

            if context in zap.context.context_list:
                zap.context.remove_context(context)
            
            context_id = zap.context.new_context(context)

            domain = urlparse(target)
            domain_path = domain.netloc
            domain_protocol = domain.scheme

            zap.context.exclude_from_context(context, f"{domain_protocol}://{domain_path}/.*")
            zap.context.include_in_context(context, f"{target}.*")

            logger.info('Accessing target {}'.format(target))
            zap.urlopen(target)
            time.sleep(2)

            scanid = zap.ascan.scan(target)

            response.data = {
                "target": target,
                "host": domain.netloc,
                "status": "started",
                "scan_id": scanid
            }

            return response
            
        except Exception as error:
            response.success = False
            response.message = f"{type(error).__name__}: {error}"
            return response

    def progress_scan(scan_id: int, context_name: str, only_high: bool = True) -> any:
        """
        Get the scan status
        
        Args:
            scan_id (int): The id of scan DAST
            context_name (str): The context to vincule the scan
            only_high (bool): Show only high alerts

        This function return percentage status of scan
        """

        response = utils.Response()

        OWASP_API_KEY: str = os.getenv('OWASP_API_KEY') if os.getenv('OWASP_API_KEY') else None

        try:
            apikey = OWASP_API_KEY
            curr_time = datetime.now()
            formatted_time = curr_time.strftime('%H%M%S')


            if not utils.isValidStr(apikey):
                response.success = False
                response.message = "Invalid configurations, contact suporte [#001]"
                return response
            
            if not utils.isValidInt(scan_id):
                response.success = False
                response.message = "Invalid scan_id value, send valid scan_id [#002]"
                return response
            
            if not utils.isValidStr(context_name):
                response.success = False
                response.message = "Invalid context value, send valid string [#003]"
                return response

            context = context_name if utils.isValidStr(context_name) else formatted_time
            
            # By default ZAP API client will connect to port 8080
            zap = ZAPv2(apikey=apikey)
            
            context_id = zap.context.set_context_in_scope(contextname=context, booleaninscope=True)
            scan_staus = int(zap.ascan.status(scan_id))

            response.data = {
                "percentage": scan_staus,
                "progress": 'Scan progress %: {}'.format(scan_staus),
                "status": "running" if scan_staus < 100 else "finished",
                "scan_id": scan_id,
                "reports": None,
            }

            if scan_staus == 100:
                alerts = zap.core.alerts()
                response.data['reports'] = []
                if only_high:
                    for alert in alerts:
                        if alert['confidence'] == 'High':
                            response.data['reports'].append(alert)
                else:
                    response.data['reports'] = alerts

            return response
            
        except Exception as error:
            response.success = False
            response.message = f"{type(error).__name__}: {error}"
            return response