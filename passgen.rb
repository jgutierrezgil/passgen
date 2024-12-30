#!/usr/bin/env ruby
# frozen_string_literal: true

require 'securerandom' # SecureRandom provides a cryptographically secure random number generator
require 'logger' # Logger provides a simple logging facility

# PasswordGenerator: A secure password generation and analysis tool
# Security features:
# - Uses Ruby's SecureRandom for cryptographically secure random number generation
# - Implements OWASP password guidelines
# - Includes password strength analysis based on multiple factors
# - Logs generation attempts for security auditing
# - Input validation to prevent buffer overflow attacks
class PasswordGenerator

  # Constants
  ALPHANUMERIC_CHARS = [('a'..'z'), ('A'..'Z'), ('0'..'9')].map(&:to_a).flatten.freeze
  SPECIAL_CHARS = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '/'].freeze
  
  def initialize(min_length: 8, max_length: 100)
    @min_length = min_length
    @max_length = max_length
    @all_chars = ALPHANUMERIC_CHARS + SPECIAL_CHARS
    @logger = Logger.new('password_generator.log')
    @strength_analyzer = PasswordStrengthAnalyzer.new
  end

  def generate!(length, include_special: true)
    validate_input!(length)
    log_generation_attempt(length, include_special)
    
    password = generate_secure_password(length, include_special)
    strength_result = @strength_analyzer.analyze(password)
    
    {
      password: password,
      strength: strength_result
    }
  rescue StandardError => e
    log_error(e)
    raise
  end

  private

  def validate_input!(length)
    unless length.is_a?(Integer) && length.between?(@min_length, @max_length)
      raise ArgumentError, "Length must be between #{@min_length} and #{@max_length}"
    end
  end

  def generate_secure_password(length, include_special)
    chars = include_special ? @all_chars : ALPHANUMERIC_CHARS
    Array.new(length) { chars.sample(random: SecureRandom) }.join
  end

  def log_generation_attempt(length, include_special)
    @logger.info("Password generation attempt - Length: #{length}, Special chars: #{include_special}")
  end

  def log_error(error)
    @logger.error("Error in password generation: #{error.message}")
  end
end

# PasswordStrengthAnalyzer: Implements NIST password guidelines
# Analyzes password strength based on:
# - Length
# - Character complexity
# - Pattern detection
# - Common password detection
class PasswordStrengthAnalyzer
  def initialize
    @common_passwords = load_common_passwords
  end

  def analyze(password)
    score = calculate_base_score(password)
    score -= penalty_for_common_patterns(password)
    score -= penalty_for_common_password(password)

    {
      score: score,
      strength: calculate_strength(score),
      details: generate_analysis_details(password)
    }
  end

  private

  def calculate_base_score(password)
    score = 0
    score += password.length >= 12 ? 2 : 1
    score += 2 if password.match?(/[A-Z]/)
    score += 2 if password.match?(/[a-z]/)
    score += 2 if password.match?(/\d/)
    score += 2 if password.match?(/[^A-Za-z0-9]/)
    score
  end

  def penalty_for_common_patterns(password)
    penalty = 0
    penalty += 2 if password.match?(/123|abc|qwerty/i)
    penalty += 2 if password.match?(/(.)\\1{2,}/)  # Repeated characters
    penalty
  end

  def penalty_for_common_password(password)
    @common_passwords.include?(password.downcase) ? 5 : 0
  end

  def calculate_strength(score)
    case score
    when 0..4 then :weak
    when 5..7 then :medium
    else :strong
    end
  end

  def generate_analysis_details(password)
    {
      length: password.length,
      has_uppercase: password.match?(/[A-Z]/),
      has_lowercase: password.match?(/[a-z]/),
      has_numbers: password.match?(/\d/),
      has_special: password.match?(/[^A-Za-z0-9]/),
      has_common_patterns: password.match?(/123|abc|qwerty/i)
    }
  end

  def load_common_passwords
    # En un caso real, cargaríamos de un archivo
    ['password', '123456', 'qwerty'].freeze
  end
end

# Ejemplo de uso
if __FILE__ == $PROGRAM_NAME
  generator = PasswordGenerator.new
  
  puts "=== Secure Password Generator ==="
  print "Enter desired password length (8-100): "
  length = gets.chomp.to_i

  print "Include special characters? (y/N): "
  include_special = gets.chomp.downcase == 'y' # Include special characters? 

  begin
    result = generator.generate!(length, include_special: include_special)
    puts "\nGenerated Password: #{result[:password]}"
    puts "Strength: #{result[:strength][:strength]}"
    puts "Score: #{result[:strength][:score]}"
    puts "\nStrength Analysis:"
    result[:strength][:details].each do |check, passed|
      puts "- #{check}: #{passed}"
    end
  rescue ArgumentError => e
    puts "Error: #{e.message}"
  end
end