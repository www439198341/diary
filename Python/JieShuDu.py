question = [0,0,5,3,0,0,0,0,0,8,0,0,0,0,0,0,2,0,0,7,0,0,1,0,5,0,0,4,0,0,0,0,5,3,0,0,0,1,0,0,7,0,0,0,6,0,0,3,2,0,0,0,8,0,0,6,0,5,0,0,0,0,9,0,0,4,0,0,0,0,3,0,0,0,0,0,0,9,7,0,0]


class ShuDu:
    def __init__(self, puzzle):
        self.a = []
        self.b = []
        self.c = [[0] * 9 for i in range(9)]
        self.puzzle = puzzle[:]
        self.answer = self.puzzle[:]
        self.update()

    def update(self):
        self.puzzle = self.answer[:]
        self.a = []
        for i in range(9):
            temp = []
            for j in range(9):
                n = self.answer[i * 9 + j]
                temp.append(n)
            self.a.append(temp)

        self.b = []
        for i in range(9):
            temp = []
            for j in range(9):
                n = self.answer[i + j * 9]
                temp.append(n)
            self.b.append(temp)

        for index in range(len(self.answer)):
            i = (index // 9 // 3) * 3 + index % 9 // 3
            j = (index // 9 % 3) * 3 + index % 9 % 3
            self.c[i][j] = self.answer[index]

    def set_answer(self, number, index):
        self.answer[index] = number

    def get_answer(self):
        return self.answer

    def get_possible_answer(self, index):
        possible_answer = []
        if self.answer[index] != 0:
            possible_answer = [self.answer[index]]
        else:
            for i in range(1, 10):
                related_a = self.a[index // 9]
                related_b = self.b[index % 9]
                related_c = self.c[(index // 9) // 3 * 3 + (index % 9) // 3]
                if i not in related_a and i not in related_b and i not in related_c:
                    possible_answer.append(i)
                if len(possible_answer) > 1:
                    break
        return possible_answer

    def set_possible_answer(self, index):
        possible_answer = self.get_possible_answer(index)
        if len(possible_answer) == 1:
            self.answer[index] = possible_answer[0]
            if self.puzzle != self.get_answer():
                self.update()

    def get_possible_index_4a(self, index: int, number: int):
        possible_location = []
        for i in range(9):
            related_a = self.a[index]
            related_b = self.b[i]
            t_index = index * 9 + i
            related_c = self.c[(t_index // 9) // 3 * 3 + (t_index % 9) // 3]
            if self.a[index][i] == 0:
                if number not in related_a and number not in related_b and number not in related_c:
                    possible_location.append(i)
                    if len(possible_location) > 1:
                        break
        if len(possible_location) == 1:
            self.set_answer(number, index * 9 + possible_location[0])
            return possible_location[0]

    def loop4a(self):
        for i in range(1, 10):
            for j in range(9):
                self.get_possible_index_4a(j, i)
                if self.puzzle != self.get_answer():
                    self.update()
                    self.loop4a()

    def loop_process(self):
        for i in range(len(self.answer)):
            self.set_possible_answer(i)
            if self.puzzle != self.get_answer():
                self.loop_process()

    def get_count(self):
        count = 0
        for n in self.get_answer():
            if n == 0:
                count += 1
        return count

    def run(self):
        while self.get_count() != 0:
            self.loop_process()
            self.loop4a()
        for line in self.a:
            print(line)


sd = ShuDu(question)
sd.run()
