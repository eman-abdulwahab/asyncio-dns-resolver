import asyncio
import logging
import dns.resolver
import dns.rrset
from typing import Tuple
from dns.asyncresolver import Resolver


async def dns_query(domain: str, rtype: str = 'A', **kwargs):
    # create an asyncio Resolver instance
    rs = Resolver()
    rs.nameservers = [
        "8.8.4.4",
        "8.8.8.8",
        "1.0.0.1",
        "80.95.220.186",
        "94.200.27.186",
        "109.228.0.238",
        "1.1.1.1",
        "64.6.64.6",
        "208.67.220.220"
    ]

    # call and asynchronously await .resolve() to obtain the DNS results
    res: dns.resolver.Answer = await rs.resolve(domain, rdtype=rtype, **kwargs)

    # we return the most useful part of Answer: the RRset, which contains
    # the individual records that were found.
    answers = []
    for answer in res:
        answers.append(str(answer).strip('"').strip('.'))

    return answers


async def dns_bulk(*queries: Tuple[str, str], **kwargs):
    ret_ex = kwargs.pop('return_exceptions', True)
    coros = [dns_query(dom, rt, **kwargs) for dom, rt in list(queries)]

    return await asyncio.gather(*coros, return_exceptions=ret_ex)


async def get_dns_records_async(domain_name, selectors=None):
    if not selectors:
        selectors = [
            "default",
            "email",
            "20170208",
            "google",
            "google2048",
            "google1024",
            "mail",
            "selector",
            "selector1",
            "selector2",
            "selector3",
            "smtpapi",
            "s1024",
            "s2048",
            "s1",
            "s2",
            "out",
            "mimecast20170111",
            "mx",
            "664B7EFE-ECE5-11E8-BF34-050C4FD4A569",
            "fpkey3642-2",
        ]

    queries = [
        (f'_dmarc.{domain_name}', 'TXT'),
        (f'{domain_name}', 'TXT'),
        (f'{domain_name}', 'A'),
        (f'{domain_name}', 'MX'),
        (f'{domain_name}', 'NS'),
        (f'{domain_name}', 'CNAME')
    ]
    for selector in selectors:
        queries.append((f"{selector}._domainkey.{domain_name}", "TXT"))

    coros = [dns_query(dom, rt) for dom, rt in list(queries)]

    result = {
        "A_records": [],
        "CNAME_records": [],
        "NS_records": [],
        "MX_records": [],
        "TXT_records": [],
        "SPF_records": [],
        "DMARC_records": [],
        "DKIM_records": []
    }

    res = await asyncio.gather(*coros, return_exceptions=True)
    for i, a in enumerate(res):
        if isinstance(a, Exception):
            logging.debug(
                f" [!!!] Error: Result {i} is an exception! Original query: {queries[i]} || Exception is: {type(a)} - {a!s} \n")
            continue

        rt = queries[i][1]
        if rt == 'A' or rt == 'MX' or rt == 'NS' or rt == 'CNAME':
            result[f'{rt}_records'] = a
        else:
            qname = queries[i][0]
            if qname.startswith('_dmarc.'):
                result['DMARC_records'] = a
            elif '_domainkey' in qname:

                record = {
                    "selector": qname.split('.')[0],
                    "records": []
                }
                for dkim in a:
                    if dkim.startswith('p=') or ';p=' in dkim or ' p=' in dkim or 'v=dkim1' in dkim.lower():
                        record['records'].append(dkim.replace("\" \"", ""))

                # to eliminate default dkim returning for all selectors
                if record['records']:
                    if not result['DKIM_records'] or result['DKIM_records'][0]['records'][0] != record['records'][0]:
                        result['DKIM_records'].append(record)
            else:
                for txt_record in a:
                    # append txt records
                    result['TXT_records'].append(txt_record)

                    # append spf records
                    if txt_record.lower().startswith('v=spf1 '):
                        result['SPF_records'].append(txt_record)

    return result


async def main():
    domains = ['edxlabs.com', 'ctm360.com', 'nbk.com', 'gib.com', 'dmarc360.com']
    for domain in domains:
        res = await get_dns_records_async(domain)
        print(f'----------- Result for  {domain} ------------')
        print(res)


if __name__ == '__main__':
    asyncio.run(main())
