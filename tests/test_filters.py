from darwin_ssl_sniffer.sniffer import EntryHash, Filters

entry = EntryHash(pid=1, process_name='Test', image='Test_image', domain='TestDomain')
entry2 = EntryHash(pid=2, process_name='Test2', image='Test_image2', domain='TestDomain2')


def test_whitelist():
    test_filter = Filters(pids=(1,), black_list=False)
    true_entry, false_entry = entry, entry2
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False

    test_filter = Filters(process_names=('Test',), black_list=False)
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False

    test_filter = Filters(images=('Test_image',), black_list=False)
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False


def test_blacklist():
    test_filter = Filters(pids=(1,), black_list=True)
    true_entry, false_entry = entry2, entry
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False

    test_filter = Filters(process_names=('Test',), black_list=True)
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False

    test_filter = Filters(images=('Test_image',), black_list=True)
    assert test_filter.should_keep(true_entry) is True
    assert test_filter.should_keep(false_entry) is False
