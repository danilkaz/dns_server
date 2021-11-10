from dataclasses import dataclass


@dataclass
class Header:
    id: int
    flags: int
    qd_count: int
    an_count: int
    ns_count: int
    ar_count: int

    def to_bytes(self) -> bytes:
        identifier = self.id.to_bytes(2, byteorder='big')
        flags = self.flags.to_bytes(2, byteorder='big')
        qd_count = self.qd_count.to_bytes(2, byteorder='big')
        an_count = self.an_count.to_bytes(2, byteorder='big')
        ns_count = self.ns_count.to_bytes(2, byteorder='big')
        ar_count = self.ar_count.to_bytes(2, byteorder='big')

        return identifier + flags + qd_count + an_count + ns_count + ar_count


@dataclass
class Question:
    q_name: bytes
    q_type: int
    q_class: int
    length: int = 0

    def to_bytes(self) -> bytes:
        q_name = bytes_to_q_name(self.q_name)
        q_type = self.q_type.to_bytes(2, byteorder='big')
        q_class = self.q_class.to_bytes(2, byteorder='big')

        return q_name + q_type + q_class


@dataclass
class Answer:
    name: bytes
    tp: int
    cls: int
    ttl: int
    r_data: bytes
    length: int = 0

    def to_bytes(self) -> bytes:
        name = bytes_to_q_name(self.name)
        tp = self.tp.to_bytes(2, byteorder='big')
        cls = self.cls.to_bytes(2, byteorder='big')
        ttl = self.ttl.to_bytes(4, byteorder='big')
        rd_length = len(self.r_data).to_bytes(2, byteorder='big')

        return name + tp + cls + ttl + rd_length + self.r_data


@dataclass
class DNSPackage:
    header: Header
    questions: list[Question]
    answers: list[Answer]
    authorities: list[Answer]
    additionals: list[Answer]

    def to_bytes(self) -> bytes:
        header = self.header.to_bytes()
        question = b''.join([q.to_bytes() for q in self.questions])
        answer = b''.join([a.to_bytes() for a in self.answers])
        authority = b''.join([a.to_bytes() for a in self.authorities])
        additional = b''.join([a.to_bytes() for a in self.additionals])

        return header + question + answer + authority + additional


def bytes_to_q_name(data: bytes) -> bytes:
    return b''.join(map(lambda x: len(x).to_bytes(1, byteorder='big') + x,
                        data.split(b'.'))) + b'\x00'
