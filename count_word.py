def count_words_in_file(input_file_path, output_file_path):
    try:
        with open(input_file_path, 'r', encoding='utf-8') as file:
            text = file.read()
            word_list = text.split()
            word_count = len(word_list)

        with open(output_file_path, 'w', encoding='utf-8') as out_file:
            out_file.write(f"Word count: {word_count}\n")
        
        print(f"Word count saved to {output_file_path}")
    
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage:
input_file = 'input.txt'
output_file = 'word_count.txt'
count_words_in_file(input_file, output_file)
