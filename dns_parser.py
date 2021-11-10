from components import Header, Question, Answer, DNSPackage


class Parser:
    def __init__(self, data: bytes):
        self.data = data

        self.header = None
        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def parse(self) -> DNSPackage:
        self.parse_header()
        start = 12
        for _ in range(self.header.qd_count):
            question = self.parse_question(start)
            start += question.length
            self.questions.append(question)
        for i in range(self.header.an_count
                       + self.header.ns_count
                       + self.header.ar_count):
            answer = self.parse_answer(start)
            start += answer.length
            if 0 <= i < self.header.an_count:
                self.answers.append(answer)
            elif self.header.an_count \
                    <= i < self.header.an_count + self.header.ns_count:
                self.authorities.append(answer)
            else:
                self.additionals.append(answer)

        return DNSPackage(self.header, self.questions,
                          self.answers, self.authorities, self.additionals)

    def parse_header(self) -> Header:
        header = self.data[:12]

        identifier = int.from_bytes(header[:2], byteorder='big')
        flags = int.from_bytes(header[2:4], byteorder='big')
        qd_count = int.from_bytes(header[4:6], byteorder='big')
        an_count = int.from_bytes(header[6:8], byteorder='big')
        ns_count = int.from_bytes(header[8:10], byteorder='big')
        ar_count = int.from_bytes(header[10:], byteorder='big')

        self.header = Header(identifier, flags,
                             qd_count, an_count, ns_count, ar_count)
        return self.header

    def parse_question(self, start: int) -> Question:
        q_name, index = self.get_qname_and_first_index_after_it(start)
        q_type = int.from_bytes(self.data[index:index + 2],
                                byteorder='big')
        q_class = int.from_bytes(self.data[index + 2: index + 4],
                                 byteorder='big')
        return Question(q_name, q_type, q_class, length=index + 4 - start)

    def get_qname_and_first_index_after_it(self,
                                           start: int) -> tuple[bytes, int]:
        labels = []
        index, finish = start, start

        while True:
            pointer = self.data[index]
            if pointer == 0:
                return b'.'.join(labels), finish + 1
            if pointer >> 6 == 3:
                finish = max(finish, index + 1)
                index = (((pointer << 2) & 0xFF) << 6) | self.data[index + 1]
            else:
                labels.append(self.data[index + 1:index + 1 + pointer])
                index += pointer + 1
            finish = max(finish, index)

    def parse_answer(self, start: int) -> Answer:
        name, index = self.get_qname_and_first_index_after_it(start)
        tp = int.from_bytes(self.data[index:index + 2], byteorder='big')
        cls = int.from_bytes(self.data[index + 2:index + 4], byteorder='big')
        ttl = int.from_bytes(self.data[index + 4:index + 8], byteorder='big')
        rd_length = int.from_bytes(self.data[index + 8:index + 10],
                                   byteorder='big')
        r_data = self.data[index + 10:index + 10 + rd_length]

        if tp == 2:
            r_data, _ = self.get_qname_and_first_index_after_it(index + 10)

        return Answer(name, tp, cls, ttl, r_data,
                      length=index + 10 + rd_length - start)

    @staticmethod
    def bin_to_bytes(data: bytes, length: int = 16) -> str:
        return bin(int.from_bytes(data, byteorder='big'))[2:].zfill(length)
