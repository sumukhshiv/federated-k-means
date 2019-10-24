add_definitions (-D__LOG_COVERT_CPP__)
add_example (chi2 main.cpp)

add_custom_target (example-chi2-run
  COMMAND $<TARGET_FILE:example-chi2>
  DEPENDS example-chi2
  COMMENT "Running the Covert C++ chi-square example"
  USES_TERMINAL
)
set_target_properties (example-chi2-run
  PROPERTIES
    FOLDER "Examples"
)