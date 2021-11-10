import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from components import DNSPackage, Question
from config import ROOT, HOST, PORT, DNS_PORT
from dns_parser import Parser


def walk_through_server(raw_question_package: bytes, ip: str = ROOT) -> bytes:
    package, raw_package = send_request_and_get_packages(
        ip, raw_question_package)
    if is_package_with_error(package) or len(package.answers) > 0:
        return raw_package
    matched_records = match_ns_and_additional_records(package)
    for ns in matched_records.keys():
        ns_ip = get_ipv4_address(matched_records[ns])
        response_from_ns = walk_through_server(raw_question_package, ns_ip)
        parsed = Parser(response_from_ns).parse()
        if is_package_with_error(parsed) or len(parsed.answers) > 0:
            return response_from_ns
    if len(matched_records) == 0:
        question_package = Parser(raw_question_package).parse()
        question_package.header.qd_count = 1
        question_package.header.ar_count = 0
        question_package.additionals = []
        for ns in package.authorities:
            question_package.questions = [Question(q_name=ns.r_data,
                                                   q_type=1, q_class=1)]
            response = walk_through_server(question_package.to_bytes(), ROOT)
            parsed = Parser(response).parse()
            if is_package_with_error(parsed):
                return response
            if len(parsed.answers) > 0:
                return walk_through_server(
                    raw_question_package,
                    get_ipv4_address(parsed.answers[0].r_data))
    return raw_package


def send_request_and_get_packages(ip: str, raw_package: bytes) \
        -> tuple[DNSPackage, bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.sendto(raw_package, (ip, DNS_PORT))
        data = connection.recv(4096)

    package = Parser(data).parse()
    return package, data


def match_ns_and_additional_records(package: DNSPackage) -> dict[bytes, bytes]:
    result = dict()
    ns_records = package.authorities
    additional_records = package.additionals
    for ns in ns_records:
        for additional in additional_records:
            if ns.r_data == additional.name \
                    and ns.tp == 2 and additional.tp == 1:
                result[ns.r_data] = additional.r_data
    return result


def get_ipv4_address(data: bytes) -> str:
    return '.'.join(map(str, data))


def is_package_with_error(package: DNSPackage) -> bool:
    soa = [record.tp == 6 for record in package.authorities]
    return package.header.flags & 15 != 0 or all(soa) and len(soa) > 0


def main():
    with ThreadPoolExecutor() as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((HOST, PORT))
            print(f'Serving on {HOST}')
            while True:
                data, addr = server.recvfrom(4096)
                future = executor.submit(walk_through_server,
                                         raw_question_package=data)
                try:
                    server.sendto(future.result(timeout=3), addr)
                except TimeoutError:
                    error_package = Parser(data).parse()
                    error_package.header.ar_count = 0
                    error_package.additionals = []
                    error_package.header.flags |= 32770
                    server.sendto(error_package.to_bytes(), addr)


if __name__ == '__main__':
    main()
