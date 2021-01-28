Feature: Division 
Scenario Outline: Add two numbers <num1> & <num2>
    Given I have a calculator
    When I perfor division for <num1> and <num2>
    Then the result should be <total>
 
  Examples: 
    | num1 | num2 | total |
    | 15   | 5    | 3 	  |
    | 55   | 15   | 3.7   |
    | 133  | 32   | 4.2   |
    | 33   | 10   | 3.3   |
	
	 