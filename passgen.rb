require 'securerandom'

ALPHANUMERIC_CHARACTERS = [('a'..'z'), ('A'..'Z'), ('0'..'9')].map(&:to_a).flatten
SPECIAL_CHARACTERS = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '/', '\\', ',', '.', ';', ':', '(', ')', '[', ']', '{', '}', '|', '?', '¿', '¡', '!', '+', '=', '<', '>', '~', '`']
ALL_CHARACTERS = ALPHANUMERIC_CHARACTERS + SPECIAL_CHARACTERS

def generate_password(length, include_special_characters = true)
    characters_size = ALPHANUMERIC_CHARACTERS.size
    special_characters_size = SPECIAL_CHARACTERS.size
    
    if !include_special_characters
        (0...length).map { ALPHANUMERIC_CHARACTERS[SecureRandom.random_number(characters_size)] }.join
    else
        all_characters_size = characters_size + special_characters_size
        (0...length).map { ALL_CHARACTERS[SecureRandom.random_number(all_characters_size)] }.join
    end
end

# Ask the user for the password length
puts "How many characters should your password have?"
length_password = gets.chomp.to_i

# Check that the length is a valid number and that it is greater than 8
if length_password < 8 || length_password > 100
    puts "You must enter a number that is an integer and between 8 and 100"
    exit
end

puts "The password will use numbers and letters (uppercase and lowercase), Do you want to add special characters? (yes/no)"
special_characters = gets.chomp.downcase

if special_characters == "yes"
    special_characters = true
elsif special_characters == "no"
    special_characters = false
else
    special_characters = true
end

puts "Generating password..."
puts "Your generated password is: #{generate_password(length_password, special_characters)}"