"""Local Streamlit dashboard for cisco_cve_checker.py output."""
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title='Cisco CVE Dashboard', page_icon='🛡️', layout='wide')
ROOT = Path(__file__).resolve().parent
FIELDS = ['id','hostname','model','firmware','product_family','mapping_status','advisory_id','cve','title','severity','cvss_score','published','last_updated','fixed_version','vulnerability_status','scan_status','match_reason','query_errors','advisory_url','csaf_url']
REQUIRED = {'id','hostname','model','firmware','cve','vulnerability_status','scan_status'}
STATUS = ['VULNERABLE','POTENTIALLY_VULNERABLE','NOT_AFFECTED','NO_MATCHES_FOUND','UNKNOWN','SCAN_ERROR']
SEVERITY = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']

def normalize(df):
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError('Colunas em falta: ' + ', '.join(sorted(missing)))
    df = df.copy()
    for col in FIELDS:
        if col not in df: df[col] = ''
        df[col] = df[col].fillna('').astype(str).str.strip()
    for col in ['severity','vulnerability_status','scan_status']:
        df[col] = df[col].str.upper().replace('', 'UNKNOWN')
    df['severity'] = df['severity'].replace({'INFORMATIONAL':'UNKNOWN','MODERATE':'MEDIUM'})
    df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
    df['device'] = df['hostname'] + ' [' + df['id'] + ']'
    df['valid_cve'] = df['cve'].str.fullmatch(r'CVE-\d{4}-\d{4,}', case=False, na=False)
    df['cve'] = df['cve'].str.upper()
    return df

def pairs(df):
    return df[df['valid_cve']].drop_duplicates(['device','cve'])

def safe_csv(df):
    df = df.copy()
    for col in df.select_dtypes(include=['object','string']).columns:
        df[col] = df[col].map(lambda x: "'"+x if isinstance(x,str) and x.lstrip().startswith(('=','+','-','@')) else x)
    return df.to_csv(index=False).encode('utf-8-sig')

st.title('Cisco · Vulnerability Dashboard')
st.caption('Análise local do inventário e dos resultados Cisco PSIRT. Não executa novos pedidos à API.')
with st.sidebar:
    st.header('Fonte de dados')
    upload = st.file_uploader('Carregar CSV alternativo', type=['csv'])
    if st.button('Recarregar dados'): st.rerun()
try:
    source = upload if upload is not None else ROOT / 'cve_results.csv'
    raw = normalize(pd.read_csv(source, dtype=str, keep_default_na=False, encoding='utf-8-sig'))
except (OSError, ValueError, pd.errors.ParserError) as exc:
    st.error(f'Não foi possível ler os resultados: {exc}')
    st.info('Coloca cve_results.csv junto ao script ou carrega-o na barra lateral.')
    st.stop()
if raw.empty:
    st.warning('O CSV não contém registos.'); st.stop()
with st.sidebar:
    st.header('Filtros')
    filters = {}
    for col,label in [('device','Equipamento'),('model','Modelo'),('firmware','Firmware'),('severity','Severidade'),('vulnerability_status','Aplicabilidade'),('scan_status','Estado da pesquisa')]:
        filters[col] = st.multiselect(label, sorted(raw[col].unique()))
    query = st.text_input('Pesquisar CVE, título ou advisory')
    hide = st.checkbox('Ocultar não afetados e linhas sem CVE', value=False)
df = raw.copy()
for col, values in filters.items():
    if values: df = df[df[col].isin(values)]
if query.strip():
    mask = pd.Series(False,index=df.index)
    for col in ['cve','title','advisory_id']:
        mask |= df[col].str.contains(query.strip(),case=False,regex=False)
    df = df[mask]
if hide: df = df[df['valid_cve'] & (df['vulnerability_status'] != 'NOT_AFFECTED')]
confirmed = pairs(df[df['vulnerability_status']=='VULNERABLE'])
potential = pairs(df[df['vulnerability_status']=='POTENTIALLY_VULNERABLE'])
potential = potential.merge(confirmed[['device','cve']],on=['device','cve'],how='left',indicator=True).query("_merge == 'left_only'")
cols = st.columns(5)
for col,label,val in zip(cols,['Equipamentos','CVEs distintos','Pares confirmados','Pares potenciais','Equip. com falhas'],[df.device.nunique(),df.loc[df.valid_cve,'cve'].nunique(),len(confirmed),len(potential),df.loc[df.scan_status.isin(['PARTIAL','SCAN_ERROR']),'device'].nunique()]):
    col.metric(label,val)
st.caption(f'{len(df)} registos filtrados de {len(raw)}. Pares = equipamento + CVE; confirmados têm precedência sobre potenciais nos indicadores.')
if df.empty:
    st.warning('Nenhum resultado corresponde aos filtros.'); st.stop()
if raw.scan_status.isin(['PARTIAL','SCAN_ERROR']).any():
    st.warning('Existem pesquisas parciais ou com erro no ficheiro original. Consulta a secção Qualidade dos dados.')
if raw.mapping_status.eq('candidate_generic').any():
    st.info('Existem correspondências genéricas de produto que precisam de validação.')
summary,devices,findings,quality = st.tabs(['Visão geral','Equipamentos','Vulnerabilidades','Qualidade dos dados'])
with summary:
    a,b = st.columns(2)
    with a:
        st.subheader('Severidade dos CVEs candidatos')
        candidates = pd.concat([confirmed,potential.drop(columns='_merge')],ignore_index=True)
        if candidates.empty: st.info('Sem pares confirmados ou potenciais no filtro.')
        else:
            chart = candidates.groupby(['severity','vulnerability_status']).size().unstack(fill_value=0)
            chart = chart.reindex([s for s in SEVERITY if s in chart.index]+[s for s in chart.index if s not in SEVERITY])
            st.bar_chart(chart)
    with b:
        st.subheader('Estados de aplicabilidade')
        st.bar_chart(df.drop_duplicates(['device','cve','vulnerability_status']).groupby('vulnerability_status').size().rename('Registos'))
    st.subheader('Equipamentos com mais CVEs candidatos')
    counts = pd.DataFrame({'Confirmados':confirmed.groupby('device').size(),'Potenciais':potential.groupby('device').size()}).fillna(0).astype(int)
    if not counts.empty: st.bar_chart(counts.sort_values(['Confirmados','Potenciais'],ascending=False))
    else: st.info('Sem CVEs candidatos.')
with devices:
    st.subheader('Resumo por equipamento')
    base = df.groupby('device').agg(modelo=('model','first'),firmware=('firmware','first'),pesquisa=('scan_status',lambda x:', '.join(sorted(set(x)))))
    base['Confirmados'] = confirmed.groupby('device').size()
    base['Potenciais'] = potential.groupby('device').size()
    base[['Confirmados','Potenciais']] = base[['Confirmados','Potenciais']].fillna(0).astype(int)
    st.dataframe(base.sort_values(['Confirmados','Potenciais'],ascending=False),use_container_width=True)
    device = st.selectbox('Detalhes do equipamento',sorted(df.device.unique()))
    selected = df[df.device==device]
    st.dataframe(selected[['cve','title','severity','cvss_score','vulnerability_status','fixed_version','scan_status','advisory_url']],hide_index=True,use_container_width=True,column_config={'advisory_url':st.column_config.LinkColumn('Advisory oficial',display_text='Abrir')})
with findings:
    st.subheader('Resultados detalhados')
    order = {s:i for i,s in enumerate(STATUS)}
    view = df.assign(_rank=df.vulnerability_status.map(order).fillna(99)).sort_values(['_rank','cvss_score'],ascending=[True,False])
    st.dataframe(view[['device','model','firmware','cve','severity','cvss_score','vulnerability_status','fixed_version','title','advisory_url']],hide_index=True,use_container_width=True,column_config={'advisory_url':st.column_config.LinkColumn('Advisory oficial',display_text='Abrir')})
    choices = sorted(df.loc[df.valid_cve,'cve'].unique())
    if choices:
        cve = st.selectbox('Consultar evidências de um CVE',choices)
        for _,r in df[df.cve==cve].iterrows():
            with st.expander(f'{r.device} — {r.vulnerability_status} — {r.advisory_id}'):
                st.write(r.title); st.write('Firmware instalado:',r.firmware); st.write('Correção indicada:',r.fixed_version or 'Não indicada'); st.write('Motivo:',r.match_reason or 'Não indicado')
                st.write('Advisory:',r.advisory_url); st.write('CSAF:',r.csaf_url)
    st.download_button('Exportar resultados filtrados',safe_csv(df[FIELDS]),'cve_results_filtered.csv','text/csv')
with quality:
    st.subheader('Cobertura e erros do ficheiro original (sem filtros)')
    problems = raw[raw.scan_status.isin(['PARTIAL','SCAN_ERROR']) | raw.vulnerability_status.isin(['UNKNOWN','NO_MATCHES_FOUND']) | raw.mapping_status.eq('candidate_generic') | raw.query_errors.ne('')]
    st.dataframe(problems[['device','model','firmware','mapping_status','scan_status','vulnerability_status','query_errors','match_reason']].drop_duplicates(),hide_index=True,use_container_width=True)
    st.caption('NO_MATCHES_FOUND não significa ausência de vulnerabilidades. Os estados são os produzidos pelo scanner; este dashboard não valida firmware nem configurações.')
