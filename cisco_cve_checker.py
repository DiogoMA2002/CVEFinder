"""Cisco PSIRT advisory discovery and conservative CSAF applicability checks."""
import csv
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
INPUT = ROOT / 'cisco_inventory.csv'
OUTPUT = ROOT / 'cve_results.csv'
CACHE = ROOT / 'cisco_cve_cache.json'
TTL = 24 * 3600
BASE = 'https://apix.cisco.com/security/advisories/v2'
TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token'
PAGE_SIZE = 100
FIELDS = ['id','hostname','model','firmware','product_family','mapping_status',
          'advisory_id','cve','title','severity','cvss_score','published',
          'last_updated','fixed_version','vulnerability_status','scan_status',
          'match_reason','query_errors','advisory_url','csaf_url']


def as_list(value):
    return value if isinstance(value, list) else [value] if value else []


class Client:
    def __init__(self):
        self.session = requests.Session()
        self.session.mount('https://', HTTPAdapter(max_retries=Retry(
            total=4, backoff_factor=2, status_forcelist=[429,500,502,503,504],
            allowed_methods={'GET'}, respect_retry_after_header=True)))
        self.token = None
        self.expiry = 0
        self.last_call = 0
        try:
            self.cache = json.loads(CACHE.read_text(encoding='utf-8'))
            if not isinstance(self.cache, dict):
                self.cache = {}
        except (OSError, ValueError):
            self.cache = {}

    def cached(self, key, fetch):
        entry = self.cache.get(key, {})
        if isinstance(entry, dict) and time.time() - entry.get('time', 0) < TTL and 'data' in entry:
            return entry['data']
        data = fetch()
        self.cache[key] = {'time': time.time(), 'data': data}
        tmp = CACHE.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.cache, ensure_ascii=False), encoding='utf-8')
        tmp.replace(CACHE)
        return data

    def authenticate(self):
        cid, secret = os.getenv('CISCO_CLIENT_ID'), os.getenv('CISCO_CLIENT_SECRET')
        if not cid or not secret:
            raise RuntimeError('Credenciais CISCO_CLIENT_ID/CISCO_CLIENT_SECRET em falta')
        r = self.session.post(TOKEN_URL, auth=(cid, secret),
                              data={'grant_type':'client_credentials'}, timeout=30)
        r.raise_for_status()
        data = r.json()
        self.token = data['access_token']
        self.expiry = time.time() + max(0, int(data.get('expires_in',3600))-60)

    def api_get(self, path, params):
        for attempt in range(2):
            if not self.token or time.time() >= self.expiry:
                self.authenticate()
            time.sleep(max(0, 2.1 - (time.monotonic() - self.last_call)))
            self.last_call = time.monotonic()
            r = self.session.get(BASE + path, params=params, timeout=90,
                                 headers={'Authorization':f'Bearer {self.token}', 'Accept':'application/json'},
                                 allow_redirects=False)
            if r.status_code == 401 and attempt == 0:
                self.token = None
                continue
            try:
                data = r.json()
            except ValueError:
                r.raise_for_status()
                raise RuntimeError('Resposta da API não é JSON')
            if not isinstance(data, dict):
                raise RuntimeError('Formato inesperado da API')
            if data.get('errorCode'):
                raise RuntimeError(str(data['errorCode']) + ': ' + str(data.get('errorMessage','')))
            if r.status_code != 200:
                raise RuntimeError(f'HTTP {r.status_code}')
            return data
        raise RuntimeError('Falha de autenticação')

    def search(self, path, params):
        key = 'query:' + json.dumps([path,params], sort_keys=True)
        def fetch():
            results, seen = [], set()
            for page in range(1,101):
                data = self.api_get(path, dict(params, summaryDetails='true',
                    productNames='true', pageIndex=page, pageSize=PAGE_SIZE))
                batch = data.get('advisories')
                if not isinstance(batch,list):
                    raise RuntimeError('Campo advisories ausente ou inválido')
                for advisory in batch:
                    if not isinstance(advisory,dict) or not advisory.get('advisoryId'):
                        raise RuntimeError('Advisory sem identificador')
                    aid = advisory['advisoryId']
                    if aid in seen:
                        raise RuntimeError('Paginação devolveu advisory repetido')
                    seen.add(aid)
                    results.append(advisory)
                paging = data.get('paging')
                if isinstance(paging,dict) and 'next' in paging:
                    if paging['next'] in (None,'','NA'):
                        return results
                    if not batch:
                        raise RuntimeError('Página vazia com continuação')
                elif len(batch) < PAGE_SIZE:
                    return results
            raise RuntimeError('Limite de paginação atingido; pesquisa incompleta')
        return self.cached(key, fetch)

    def csaf(self, url):
        def fetch():
            p = urlparse(url)
            if p.scheme != 'https' or not p.hostname or not (p.hostname == 'cisco.com' or p.hostname.endswith('.cisco.com')) or p.username or p.password:
                raise RuntimeError('URL CSAF não pertence à Cisco')
            # Never send the OAuth token to CSAF document URLs.
            r = self.session.get(url, timeout=60, headers={'Accept':'application/json'})
            r.raise_for_status()
            doc = r.json()
            if not isinstance(doc,dict) or not isinstance(doc.get('vulnerabilities'),list):
                raise RuntimeError('Documento CSAF inválido')
            return doc
        return self.cached('csaf:' + url, fetch)


def queries(row):
    if row['query_method'] == 'os_version':
        os_type = row['os_type'].lower()
        if os_type not in {'ios','iosxe','nxos','aci','asa','ftd','fmc','fxos'} or not row['firmware']:
            raise ValueError('OS ou firmware inválido')
        return [(f'/OSType/{os_type}', {'version':row['firmware']})]
    if row['query_method'] == 'product':
        names = dict.fromkeys(row[k].strip() for k in ('cisco_product_name','cisco_product_name_alt') if row.get(k,'').strip())
        if names:
            return [('/product',{'product':n}) for n in names]
    raise ValueError('Mapping em falta ou método desconhecido')


def exact_token(text, token):
    return bool(token and re.search(r'(?<![\w.\-])'+re.escape(token)+r'(?![\w.\-])', text, re.I))


def product_paths(tree):
    """Resolve explicit branch paths only; do not infer version ranges or relationships."""
    paths = {}
    def walk(branches, ancestors):
        for branch in branches:
            names = ancestors + [str(branch.get('name',''))]
            product = branch.get('product',{})
            if product.get('product_id'):
                paths[product['product_id']] = ' '.join(names + [str(product.get('name',''))])
            walk(branch.get('branches',[]), names)
    walk(tree.get('branches',[]), [])
    for product in tree.get('full_product_names',[]):
        if product.get('product_id'):
            paths[product['product_id']] = str(product.get('name',''))
    return paths


def assess(row, doc, cve):
    if not doc or not cve:
        return 'POTENTIALLY_VULNERABLE', 'Sem CSAF/CVE utilizável para validar firmware', ''
    paths = product_paths(doc.get('product_tree',{}))
    states, fixes = set(), set()
    for vuln in doc.get('vulnerabilities',[]):
        if vuln.get('cve','').upper() != cve.upper():
            continue
        for state in ('known_affected','known_not_affected','fixed','under_investigation'):
            for pid in vuln.get('product_status',{}).get(state,[]):
                name = paths.get(pid,'')
                if exact_token(name,row['model']) and exact_token(name,row['firmware']):
                    states.add(state)
    if states == {'known_affected'}:
        return 'VULNERABLE', 'CSAF known_affected: modelo e firmware explícitos; condições de exploração por rever', ''
    if states and states <= {'known_not_affected','fixed'}:
        return 'NOT_AFFECTED', 'CSAF identifica explicitamente modelo e firmware como não afetado/corrigido', row['firmware'] if 'fixed' in states else ''
    return 'POTENTIALLY_VULNERABLE', 'CSAF sem correspondência inequívoca de modelo e firmware, ou estados contraditórios', ''


def cve_ids(advisory, doc):
    values = ' '.join(map(str,as_list(advisory.get('cves'))))
    if doc:
        values += ' ' + ' '.join(str(v.get('cve','')) for v in doc.get('vulnerabilities',[]))
    return sorted(set(re.findall(r'CVE-\d{4}-\d{4,}',values.upper()))) or ['']


def base_row(row):
    return {k:row.get(k,'') for k in ('id','hostname','model','firmware','product_family','mapping_status')}


def scan(client,row):
    advisories, errors = {}, []
    try:
        plans = queries(row)
    except ValueError as exc:
        return [dict(base_row(row), vulnerability_status='UNKNOWN',scan_status='SCAN_ERROR',match_reason=str(exc))]
    successes = 0
    for path, params in plans:
        try:
            for a in client.search(path,params):
                advisories[a['advisoryId']] = a
            successes += 1
        except (requests.RequestException,ValueError,RuntimeError,OSError,KeyError) as exc:
            errors.append(f'{path} {params}: {exc}')
    status = 'COMPLETE' if not errors else 'PARTIAL' if successes else 'SCAN_ERROR'
    if not advisories:
        return [dict(base_row(row), scan_status=status, query_errors=' | '.join(errors),
                     vulnerability_status='NO_MATCHES_FOUND' if not errors and row.get('mapping_status') != 'candidate_generic' else 'UNKNOWN',
                     match_reason='Sem advisories encontrados; não comprova ausência de CVEs')]
    results = []
    for aid,a in advisories.items():
        doc, csaf_error = None, ''
        if a.get('csafUrl'):
            try:
                doc = client.csaf(a['csafUrl'])
            except (requests.RequestException,ValueError,RuntimeError,OSError,KeyError) as exc:
                csaf_error = f' | CSAF: {exc}'
        for cve in cve_ids(a,doc):
            finding, reason, fixed = assess(row,doc,cve)
            results.append(dict(base_row(row),advisory_id=aid,cve=cve,
                title=a.get('advisoryTitle',''),severity=a.get('sir',''),cvss_score=a.get('cvssBaseScore',''),
                published=a.get('firstPublished',''),last_updated=a.get('lastUpdated',''),fixed_version=fixed,
                vulnerability_status=finding,scan_status='PARTIAL' if csaf_error and status=='COMPLETE' else status,
                match_reason=reason+csaf_error,query_errors=' | '.join(errors),
                advisory_url=a.get('publicationUrl',''),csaf_url=a.get('csafUrl','')))
    return results


def main():
    with INPUT.open(encoding='utf-8-sig',newline='') as f:
        reader = csv.DictReader(f)
        required = {'id','hostname','model','firmware','product_family','mapping_status','query_method','os_type','cisco_product_name','cisco_product_name_alt'}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f'Colunas em falta: {sorted(missing)}')
        inventory = list(reader)
    client = Client()
    results = []
    for i,row in enumerate(inventory,1):
        print(f'[{i}/{len(inventory)}] {row["hostname"]} | {row["model"]} | {row["firmware"]}',flush=True)
        findings = scan(client,row)
        results.extend(findings)
        print(f'  {len(findings)} registo(s) | {findings[0]["scan_status"]}',flush=True)
    with OUTPUT.open('w',encoding='utf-8-sig',newline='') as f:
        writer = csv.DictWriter(f,fieldnames=FIELDS)
        writer.writeheader()
        # Prevent spreadsheet formula interpretation of external text.
        for row in results:
            writer.writerow({k: "'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for k,v in row.items()})
    print(f'Exportado: {OUTPUT} ({len(results)} registos)')


if __name__ == '__main__':
    main()
