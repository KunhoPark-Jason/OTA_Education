import os

def read_topics_from_file(filename="topic_list.txt"):
    """Read topics from a file and return them as a list."""
    if not os.path.exists(filename):
        print(f"File '{filename}' does not exist. Please create it with topics listed line by line.")
        return []
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file if line.strip()]

def read_file():
    """Allow the user to select a topic and read the corresponding file."""
    topics = read_topics_from_file()
    if not topics:
        print("No topics found. Exiting.")
        return

    while True:
        print("\nAvailable topics:")
        for i, topic in enumerate(topics, 1):
            print(f"{i}. {topic}")
        print("Enter the number of the topic to read its file, or 'exit' to quit.")
        
        choice = input("Your choice: ").strip()
        if choice.lower() == 'exit':
            break
        if choice.isdigit() and 1 <= int(choice) <= len(topics):
            topic = topics[int(choice) - 1]
            filename = f"{topic.replace('/', '_')}.txt"
            if os.path.exists(filename):
                print(f"\nContents of '{filename}':")
                with open(filename, 'r', encoding='utf-8') as file:
                    print(file.read())
            else:
                print(f"File '{filename}' does not exist.")
        else:
            print("Invalid choice. Please try again.")

# Example usage
if __name__ == "__main__":
    read_file()
