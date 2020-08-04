## GOOSE Traces for Evaluation

The evaluation was performed using the [IEC61850SecurityDataset](https://github.com/smartgridadsc/IEC61850SecurityDataset), which is presented in [1]. In particular, we used the following traces:

1. [Normal operation trace](https://github.com/smartgridadsc/IEC61850SecurityDataset/tree/master/Normal/No_Variable_Loading),
2. Four variants of [GOOSE poisoning](https://github.com/smartgridadsc/IEC61850SecurityDataset/tree/master/Attack/Message%20Suppression%20(MS)) attack (called message supression),
3. Three variants of [data manipulation](https://github.com/smartgridadsc/IEC61850SecurityDataset/tree/master/Attack/Data%20Manipulation%20(DM)) attack, and
4. A [combination](https://github.com/smartgridadsc/IEC61850SecurityDataset/tree/master/Attack) of poisoning and data manipulation attack.

In addition, we modified the normal operation trace to generate other benign and attack scenarios not included in the dataset. Those traces are included in this directory and explained below:

1. `NormalTrace1`: Benign GOOSE transfer, including only retransmission of a state.
2. `NormalTrace2`: Benign GOOSE transfer, including retransmission of a state and single change of state.
3. `NormalTrace3`: Benign GOOSE transfer, including retransmission and many changes of state.
4. `AttackTrace1`: Poisoning attack that injects a frame with next expected (stNum, sqNum) values (frame no. 6) and retransmits the malicious state.
5. `AttackTrace2`: Poisoning attack that injects a frame with next expected (stNum, sqNum) values (frame no. 21) and retransmits the malicious state. However, the benign communication involves the change of state.
6. `AttackTrace3`: Poisoning attack that injects a frame with next expected (stNum, sqNum) values (frame no. 6) and immediately inserts a new malicious state. However, the benign communication keeps retransmitting the old state.
7. `AttackTrace4`: Poisoning attack that injects a frame with next expected (stNum, sqNum) values (frame no. 21) and injects a new (malicious) state right before the point when the benign state change also happens.

(Note: the attack injection code is not included in order to avoid misuse.)

### References
* [1] P. P. Biswas, H. C. Tan, Q. Zhu, Y. Li, D. Mashima, and B. Chen, “A synthesized dataset for cybersecurity study of IEC 61850 based substation,” in Proc. 2019 IEEE International Conference on Communications, Control, and Computing Technologies for Smart Grids (SmartGridComm), 2019, pp. 1–7.