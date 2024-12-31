# 🔐 PassGen

Welcome to **PassGen**, a secure password generator written in Ruby that implements OWASP password guidelines and provides comprehensive password strength analysis.

## 🚀 Features

- **Secure Random Generation**: Uses Ruby's SecureRandom for cryptographically secure password generation
- **Password Strength Analysis**: Analyzes passwords based on multiple security factors:
  - Length requirements
  - Character complexity
  - Pattern detection
  - Common password checks
- **Security Logging**: Maintains a security log of password generation attempts for auditing
- **Input Validation**: Implements robust input validation to prevent security issues
- **Flexible Configuration**: 
  - Customize password length (8-100 characters)
  - Optional special characters
  - Configurable minimum and maximum lengths

## 🛠️ Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/jgutierrezgil/passgen.git
    cd passgen
    ```

2. **Install required gems**:
    ```sh
    gem install minitest  # For running tests
    gem install yard      # For generating documentation
    ```

## 📖 Usage

### Basic Usage

```sh
ruby lib/password_generator.rb
```

### As a Library

```ruby
# Create a password generator
generator = PasswordGenerator.new(min_length: 8, max_length: 100)

# Generate a password with special characters
result = generator.generate!(12, include_special: true)
puts result[:password]  # Prints the generated password
puts result[:strength]  # Shows password strength analysis

# Generate a password without special characters
result = generator.generate!(16, include_special: false)
```

### Password Strength Analysis

```ruby
analyzer = PasswordStrengthAnalyzer.new
result = analyzer.analyze("MyP@ssw0rd!")

puts result[:strength]  # :strong, :medium, or :weak
puts result[:score]    # Numerical score
puts result[:details]  # Detailed analysis
```

## 🧪 Testing

Run the test suite:

```sh
ruby test/password_generator_test.rb
```

## 📚 Documentation

Generate documentation:

```sh
yard doc lib/password_generator.rb
```

View documentation in your browser:

```sh
yard server
```

## 🔍 Code Structure

- **PasswordGenerator**: Main class for password generation
  - Implements secure random generation
  - Handles input validation
  - Integrates with strength analysis
  - Manages logging

- **PasswordStrengthAnalyzer**: Analyzes password strength
  - Scores based on multiple factors
  - Detects common patterns
  - Checks against common passwords
  - Provides detailed analysis

## 🔒 Security Features

- Cryptographically secure random number generation
- OWASP password guidelines implementation
- Password strength analysis
- Security logging
- Input validation
- Pattern detection
- Common password detection

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📜 License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## ✨ Future Improvements

- [ ] Load common passwords from external file
- [ ] Add configuration file support
- [ ] Implement password expiration tracking
- [ ] Add password history functionality
- [ ] Enhance pattern detection
- [ ] Add password policy configuration
- [ ] Implement password entropy calculation

## 📊 Test Coverage

The project includes comprehensive unit tests covering:
- Password generation
- Length validation
- Special character handling
- Strength analysis
- Error handling
- Pattern detection

## 🛡️ Security Considerations

- Uses cryptographically secure random number generation
- Implements input validation
- Provides comprehensive logging
- Follows OWASP guidelines
- Includes pattern detection
- Checks against common passwords

## 🎯 Best Practices

- Object-Oriented Design
- Comprehensive Documentation
- Unit Testing
- Error Handling
- Security Logging
- Input Validation
- Code Organization
