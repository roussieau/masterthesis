# File explanation
All the files that are stored in this folder are dumps of our database that were made at different period of time.
For some of them, the title describes when the dump has actually been made.
The other ones deserve a bit more explanation :

- .Merged.csv : datasets generated by Thomas Given-Wilson
- .Merged_thomas.csv : same as previous point but parsed in order to fit in our model (feature names added, conversion from malware names to integer values)

The following datasets have been created in order to compare the performance of different machine learning algorithms when varying some parameters:

- control_8000_false_3.csv : witness sample representative of what could be considered as a "classic" dataset (8000 malwares with a 3/5 threshold, errors considered as non-packed result, all features and all detectors used)
- default_X.csv : dataset where the threshold has been set to X/5 detectors
- not_D.csv : dataset where we only considered [all detectors - D] as relevant for the analysis
- error_as_packed.csv : dataset where an "error" result from a detector is considered as a positive answer