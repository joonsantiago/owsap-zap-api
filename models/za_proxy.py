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
from models.dto.dast import ItemDast

load_dotenv()

logger = logging.getLogger('uvicorn.error')


OWASP_PROXY: str = os.getenv('OWASP_PROXY') if os.getenv('OWASP_PROXY') else '127.0.0.1'
OWASP_PROXY_PORT: str = os.getenv('OWASP_PROXY_PORT') if os.getenv('OWASP_PROXY_PORT') else '8080'
LOCAL_PROXIES = {'http': f'http://{OWASP_PROXY}:{OWASP_PROXY_PORT}', 'https': f'http://{OWASP_PROXY}:{OWASP_PROXY_PORT}'}

class ZaProxy():


    def __init__(self) -> None:
        self.start_time = time.time()
    
    def save_scan_id(scan_id: int, item: ItemDast, context_id: int | None = None, user_id: int | None = None):
        logger.info('Save scan id')
        file = open(f"{os.path.dirname(__file__)}/../scan_ids/target_scan_ids.json", "r+")
        data = json.loads(file.read())

        data.append({"scan_id": scan_id, "context": item.context, "target": item.target, "context_id": context_id, "user_id": user_id })
        file.seek(0)
        file.write(json.dumps(data))
        file.close()
        logger.info('Closed scan id')
    
    def read_scan_id(scan_id: int, context: int | None = None, user_id: int | None = None):
        logger.info('Read scan id')
        file = open(f"{os.path.dirname(__file__)}/../scan_ids/target_scan_ids.json", "r")
        data = json.loads(file.read())

        item = None
        if data is not None and len(data) > 0:
            for record in data:
                if item is not None:
                    continue

                if int(record['scan_id']) == scan_id and record['context'] == context:
                    item = record
        
        return item
        

    def start_scan_target(data: ItemDast) -> any:
        """
        Start run scan in the target URL
        
        Args:
            data (ItemDast): Values with configuration to scan DAST

        This function begin and return the ID os scan DAST
        """

        target = data.target
        context_name = data.target

        response = utils.Response()

        OWASP_API_KEY: str = os.getenv('OWASP_API_KEY') if os.getenv('OWASP_API_KEY') else None

        logger.info('Accessing target {}'.format(target))

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
            zap = ZAPv2(apikey=apikey, proxies=LOCAL_PROXIES)

            if context not in zap.context.context_list:
                context_id = zap.context.new_context(context)
                # zap.context.remove_context(context)
                # logger.info(f"Removed from context with successfuly {context}")
            else:
                context_details = zap.context.context(context)
                context_id = context_details['id']
            

            domain = urlparse(target)
            domain_path = domain.netloc
            domain_protocol = domain.scheme

            zap.context.exclude_from_context(contextname=context, regex=f"{domain_protocol}://{domain_path}/.*")
            zap.context.include_in_context(contextname=context, regex=f"{target}.*")

            scan_as_user = None

            # if data.cookies is not None and data.cookies.records is not None and len(data.cookies.records) > 0:
            #     cookie_domain = domain_path
            #     session_name = f'session_{domain_path}'
            #     session_user = f'user_{domain_path}'
            #     user_id = zap.users.new_user(contextid=context_id, name=session_user)

            #     scan_as_user = True

            #     for cookie in data.cookies.records:
            #         zap.users.set_cookie(
            #             contextid=context_id, 
            #             userid=user_id, 
            #             domain=cookie_domain,
            #             name=cookie.name,
            #             value=cookie.value,
            #             # path=cookie.path,
            #             # secure=cookie.secure
            #         )
                
            #     logger.info(f"Cookies setting to user {user_id} in context {context_name}:")
            #     cookies = zap.users.get_authentication_session(context_id, user_id)
            #     logger.info(cookies)

            logger.info('Accessing target {}'.format(target))
            zap.urlopen(target)
            time.sleep(2)

            if scan_as_user is not None:
                logger.info("Run scan by user context")
                scanid = zap.ascan.scan_as_user(
                    url=target,
                    contextid=context_id, 
                    userid=user_id
                )
            else:
                scanid = zap.ascan.scan(target)

            ZaProxy.save_scan_id(
                scan_id=scanid,
                item=data,
                context_id=context_id,
            )

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
            zap = ZAPv2(apikey=apikey, proxies=LOCAL_PROXIES)
            
            # context_id = zap.context.set_context_in_scope(contextname=context, booleaninscope=True)
            scan_staus = int(zap.ascan.status(scan_id))

            scan_record = ZaProxy.read_scan_id(
                scan_id=scan_id,
                context=context,
            )
            logger.info(f"Returning the scan_id: {scan_record['scan_id']}")

            response.data = {
                "percentage": scan_staus,
                "progress": 'Scan progress %: {}'.format(scan_staus),
                "status": "running" if scan_staus < 100 else "finished",
                "scan_id": scan_id,
                "reports": None,
            }

            if scan_staus == 100:

                if scan_record is not None and 'target' in scan_record:
                    logger.info(f"Getting alerts to baseurl {scan_record['target']}")
                    alerts = zap.core.alerts(baseurl=scan_record['target'])
                else:
                    alerts = zap.core.alerts()
                # Filtrar os alertas pelo Scan ID (sourceId)
                # alerts = [alert for alert in all_alerts if alert.get('sourceId') == scan_id]

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